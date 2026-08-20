// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Private, bounded participant-state codec used by the application crate.

use crate::channel::{Chan, RecvChan, MAX_BUFFERED};
use crate::codec::{Reader, Writer, MAX_FIELD};
use crate::dag::{Dag, MAX_OPS};
use crate::error::{Error, Result};
use crate::keys::{NodeKeys, OVERLAP};
use crate::member::{Participant, RecvState, SendState, MAX_PENDING};
use crate::membership::{Membership, Policy};
use crate::op::{Kind, Oid, Op, MAX_RECIPIENTS};
use crate::prekey::{PrekeyPool, SEAL_AFTER};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use cfr_crypto::{DhPublic, DhSecret, Secret, SigPublic, SigSecret, KEY_LEN};
use core::cell::RefCell;

type SeenVersion = (BTreeSet<Oid>, [u8; 32]);
type SeenVersions = BTreeMap<[u8; 8], SeenVersion>;

fn invalid(message: &'static str) -> Error {
    Error::Encoding(message)
}

fn usize_to_u64(value: usize) -> Result<u64> {
    u64::try_from(value).map_err(|_| invalid("state integer exceeds u64"))
}

fn read_usize(reader: &mut Reader<'_>) -> Result<usize> {
    usize::try_from(reader.u64()?).map_err(|_| invalid("state integer exceeds usize"))
}

fn write_sig_set(writer: &mut Writer, values: &BTreeSet<SigPublic>) {
    let values: Vec<SigPublic> = values.iter().copied().collect();
    writer.set(&values, |writer, value| {
        writer.bytes(value.as_bytes());
    });
}

fn read_sig_set(reader: &mut Reader<'_>, limit: usize) -> Result<BTreeSet<SigPublic>> {
    let values: Vec<SigPublic> =
        reader.set(|reader| Ok(SigPublic::from_bytes(reader.array::<32>()?)))?;
    if values.len() > limit {
        return Err(invalid("state identity set exceeds limit"));
    }
    Ok(values.into_iter().collect())
}

fn write_oid_set(writer: &mut Writer, values: &BTreeSet<Oid>) {
    let values: Vec<Oid> = values.iter().copied().collect();
    writer.set(&values, |writer, value| {
        writer.bytes(value);
    });
}

fn read_oid_set(reader: &mut Reader<'_>, limit: usize) -> Result<BTreeSet<Oid>> {
    let values: Vec<Oid> = reader.set(Reader::array::<32>)?;
    if values.len() > limit {
        return Err(invalid("state operation set exceeds limit"));
    }
    Ok(values.into_iter().collect())
}

fn ensure_strictly_ordered<T: Ord>(previous: &mut Option<T>, value: T) -> Result<()> {
    if previous.as_ref().is_some_and(|prior| prior >= &value) {
        return Err(invalid("state map is not strictly ordered"));
    }
    *previous = Some(value);
    Ok(())
}

fn write_policy(writer: &mut Writer, policy: &Policy) -> Result<()> {
    write_sig_set(writer, &policy.admins);
    writer
        .u64(usize_to_u64(policy.quorum)?)
        .u64(usize_to_u64(policy.max_ops_per_author)?);
    Ok(())
}

fn read_policy(reader: &mut Reader<'_>) -> Result<Policy> {
    let policy = Policy {
        admins: read_sig_set(reader, MAX_RECIPIENTS)?,
        quorum: read_usize(reader)?,
        max_ops_per_author: read_usize(reader)?,
    };
    if policy.quorum == 0 || policy.max_ops_per_author == 0 {
        return Err(invalid("state contains an invalid policy"));
    }
    Ok(policy)
}

fn write_prekeys(writer: &mut Writer, prekeys: &PrekeyPool) {
    writer.u32(prekeys.generation);
    match &prekeys.secret {
        Some(secret) => {
            writer.u32(1).bytes(&secret.persistence_bytes());
        }
        None => {
            writer.u32(0);
        }
    }
    writer.bytes(prekeys.public.as_bytes());
    write_sig_set(writer, &prekeys.established);
    writer.u32(prekeys.age);
}

fn read_prekeys(reader: &mut Reader<'_>) -> Result<PrekeyPool> {
    let generation = reader.u32()?;
    let secret = match reader.u32()? {
        0 => None,
        1 => Some(DhSecret::from_bytes(reader.array::<32>()?)),
        _ => return Err(invalid("state prekey presence flag is invalid")),
    };
    let public = DhPublic::from_bytes(reader.array::<32>()?);
    let established = read_sig_set(reader, MAX_RECIPIENTS)?;
    let age = reader.u32()?;
    if secret
        .as_ref()
        .is_some_and(|secret| secret.public() != public)
    {
        return Err(invalid("state prekey public and private halves differ"));
    }
    if secret.is_some() && age >= SEAL_AFTER {
        return Err(invalid("state retains an expired prekey secret"));
    }
    Ok(PrekeyPool {
        generation,
        secret,
        public,
        established,
        age,
    })
}

fn write_chan(writer: &mut Writer, chan: &Chan) {
    writer.bytes(chan.chain.as_bytes()).u64(chan.next);
}

fn read_chan(reader: &mut Reader<'_>) -> Result<Chan> {
    Ok(Chan {
        chain: Secret::from(reader.array::<KEY_LEN>()?),
        next: reader.u64()?,
    })
}

fn write_dag(writer: &mut Writer, dag: &Dag) -> Result<()> {
    let order = dag.topological();
    if order.len() != dag.len() {
        return Err(invalid("state operation graph contains a cycle"));
    }
    let operations: Vec<&Op> = order
        .iter()
        .map(|oid| {
            dag.get(oid)
                .ok_or_else(|| invalid("state operation graph is inconsistent"))
        })
        .collect::<Result<_>>()?;
    writer.list(&operations, |writer, operation| {
        operation.write(writer);
    });
    Ok(())
}

fn read_dag(reader: &mut Reader<'_>, sid: &[u8; 32]) -> Result<Dag> {
    let operations: Vec<Op> = reader.list(|reader| Op::from_wire(reader.bytes()?))?;
    if operations.is_empty() || operations.len() > MAX_OPS {
        return Err(invalid("state operation graph size is invalid"));
    }
    let mut dag = Dag::new();
    let mut seen = BTreeSet::new();
    for operation in operations {
        if &operation.sid != sid {
            return Err(invalid("state operation belongs to another session"));
        }
        operation.verify()?;
        let oid = operation.oid();
        if !seen.insert(oid) {
            return Err(invalid("state operation graph contains a duplicate"));
        }
        if !operation
            .deps
            .iter()
            .all(|dependency| seen.contains(dependency))
        {
            return Err(invalid("state operation graph is not causally ordered"));
        }
        dag.add(operation)?;
    }
    Ok(dag)
}

fn write_operations(writer: &mut Writer, operations: &[Op]) {
    writer.list(operations, |writer, operation| {
        operation.write(writer);
    });
}

fn read_operations(reader: &mut Reader<'_>, sid: &[u8; 32], limit: usize) -> Result<Vec<Op>> {
    let operations: Vec<Op> = reader.list(|reader| Op::from_wire(reader.bytes()?))?;
    if operations.len() > limit {
        return Err(invalid("state pending operation list exceeds limit"));
    }
    let mut ids = BTreeSet::new();
    for operation in &operations {
        if &operation.sid != sid {
            return Err(invalid(
                "state pending operation belongs to another session",
            ));
        }
        operation.verify()?;
        if !ids.insert(operation.oid()) {
            return Err(invalid("state pending operation list contains a duplicate"));
        }
    }
    Ok(operations)
}

fn read_peer_prekeys(
    reader: &mut Reader<'_>,
    ipk: SigPublic,
) -> Result<BTreeMap<SigPublic, (u32, DhPublic)>> {
    let entries: Vec<(SigPublic, u32, DhPublic)> = reader.list(|reader| {
        Ok((
            SigPublic::from_bytes(reader.array::<32>()?),
            reader.u32()?,
            DhPublic::from_bytes(reader.array::<32>()?),
        ))
    })?;
    if entries.len() > MAX_RECIPIENTS {
        return Err(invalid("state peer prekey map exceeds limit"));
    }
    let mut values = BTreeMap::new();
    let mut previous = None;
    for (peer, generation, public) in entries {
        ensure_strictly_ordered(&mut previous, peer)?;
        if peer == ipk {
            return Err(invalid("state contains a self peer prekey"));
        }
        values.insert(peer, (generation, public));
    }
    Ok(values)
}

fn read_send_channels(
    reader: &mut Reader<'_>,
    ipk: SigPublic,
) -> Result<BTreeMap<SigPublic, SendState>> {
    let entries: Vec<(SigPublic, Chan)> = reader.list(|reader| {
        Ok((
            SigPublic::from_bytes(reader.array::<32>()?),
            read_chan(reader)?,
        ))
    })?;
    if entries.len() > MAX_RECIPIENTS {
        return Err(invalid("state send channel map exceeds limit"));
    }
    let mut values = BTreeMap::new();
    let mut previous = None;
    for (peer, chan) in entries {
        ensure_strictly_ordered(&mut previous, peer)?;
        if peer == ipk {
            return Err(invalid("state contains a self send channel"));
        }
        values.insert(peer, SendState { chan });
    }
    Ok(values)
}

fn read_recv_chan(reader: &mut Reader<'_>) -> Result<RecvChan> {
    let chan = read_chan(reader)?;
    let entries: Vec<(u64, Vec<u8>)> =
        reader.list(|reader| Ok((reader.u64()?, reader.bytes()?.to_vec())))?;
    if entries.len() > MAX_BUFFERED {
        return Err(invalid("state receive buffer exceeds limit"));
    }
    let mut buffer = BTreeMap::new();
    let mut previous = None;
    for (sequence, payload) in entries {
        ensure_strictly_ordered(&mut previous, sequence)?;
        if sequence <= chan.next || payload.len() < 32 {
            return Err(invalid("state receive buffer entry is invalid"));
        }
        buffer.insert(sequence, payload);
    }
    Ok(RecvChan { chan, buffer })
}

fn read_recv_channels(
    reader: &mut Reader<'_>,
    ipk: SigPublic,
) -> Result<BTreeMap<SigPublic, RecvState>> {
    let entries: Vec<(SigPublic, DhPublic, RecvChan)> = reader.list(|reader| {
        Ok((
            SigPublic::from_bytes(reader.array::<32>()?),
            DhPublic::from_bytes(reader.array::<32>()?),
            read_recv_chan(reader)?,
        ))
    })?;
    if entries.len() > MAX_RECIPIENTS {
        return Err(invalid("state receive channel map exceeds limit"));
    }
    let mut values = BTreeMap::new();
    let mut previous = None;
    for (peer, eph, chan) in entries {
        ensure_strictly_ordered(&mut previous, peer)?;
        if peer == ipk {
            return Err(invalid("state contains a self receive channel"));
        }
        values.insert(peer, RecvState { eph, chan });
    }
    Ok(values)
}

fn read_nodekeys(reader: &mut Reader<'_>) -> Result<NodeKeys> {
    let capacity = read_usize(reader)?;
    if capacity == 0 || capacity > OVERLAP {
        return Err(invalid("state node-key capacity is invalid"));
    }
    let entries: Vec<(Oid, Secret<KEY_LEN>)> = reader.list(|reader| {
        Ok((
            reader.array::<32>()?,
            Secret::from(reader.array::<KEY_LEN>()?),
        ))
    })?;
    if entries.len() > capacity {
        return Err(invalid("state node-key map exceeds capacity"));
    }
    let mut keys = BTreeMap::new();
    let mut previous = None;
    for (oid, key) in entries {
        ensure_strictly_ordered(&mut previous, oid)?;
        keys.insert(oid, key);
    }
    let order: Vec<Oid> = reader.list(Reader::array::<32>)?;
    if order.len() != keys.len() {
        return Err(invalid("state node-key order length differs from map"));
    }
    let mut order_ids = BTreeSet::new();
    for oid in &order {
        if !keys.contains_key(oid) || !order_ids.insert(*oid) {
            return Err(invalid("state node-key order is inconsistent"));
        }
    }
    Ok(NodeKeys {
        keys,
        order,
        capacity,
    })
}

fn read_versions(reader: &mut Reader<'_>) -> Result<(SeenVersions, [u8; 8])> {
    let entries: Vec<([u8; 8], BTreeSet<Oid>, [u8; 32])> = reader.list(|reader| {
        Ok((
            reader.array::<8>()?,
            read_oid_set(reader, MAX_OPS)?,
            reader.array::<32>()?,
        ))
    })?;
    if entries.is_empty() || entries.len() > OVERLAP {
        return Err(invalid("state version history size is invalid"));
    }
    let mut versions = BTreeMap::new();
    let mut previous = None;
    for (version, nodes, root) in entries {
        ensure_strictly_ordered(&mut previous, version)?;
        if crate::keys::version_of(&nodes, &root) != version {
            return Err(invalid("state version binding is invalid"));
        }
        versions.insert(version, (nodes, root));
    }
    let last = reader.array::<8>()?;
    if !versions.contains_key(&last) {
        return Err(invalid("state last version is not retained"));
    }
    Ok((versions, last))
}

fn validate_contribution_state(participant: &Participant) -> Result<()> {
    let contribution_ids: BTreeSet<Oid> = participant
        .dag
        .iter()
        .filter(|(_, operation)| operation.kind() == Kind::Contrib)
        .map(|(oid, _)| *oid)
        .collect();
    if !participant.absorbed.is_disjoint(&participant.missing)
        || !participant.absorbed.is_subset(&contribution_ids)
        || !participant.missing.is_subset(&contribution_ids)
        || !participant
            .nodekeys
            .keys
            .keys()
            .all(|oid| contribution_ids.contains(oid))
    {
        return Err(invalid("state contribution tracking is inconsistent"));
    }
    if participant.pending.iter().any(|operation| {
        participant.dag.contains(&operation.oid())
            || operation
                .deps
                .iter()
                .all(|dependency| participant.dag.contains(dependency))
    }) {
        return Err(invalid("state pending operation is not pending"));
    }
    Ok(())
}

fn validate_participant(participant: &Participant) -> Result<()> {
    validate_contribution_state(participant)?;
    let members =
        Membership::new(&participant.dag, &participant.policy, &participant.guilty).members();
    if participant.prekeys.established.len() > members.len().saturating_add(1) {
        return Err(invalid("state prekey established set is inconsistent"));
    }
    for guilty in &participant.guilty {
        let proven = participant.dag.iter().any(|(_, operation)| {
            matches!(
                &operation.body,
                crate::op::Body::Accuse { who, .. } if who == guilty
            ) && participant.check_accusation(operation)
        });
        if !proven {
            return Err(invalid("state guilty set lacks valid evidence"));
        }
    }
    Ok(())
}

impl Participant {
    /// Encodes all non-derived participant state for the application boundary.
    #[doc(hidden)]
    pub fn export_persistence_state(&self) -> Result<Vec<u8>> {
        let mut writer = Writer::new();
        writer
            .bytes(&self.identity.persistence_seed())
            .bytes(self.ipk.as_bytes())
            .bytes(&self.sid);
        write_policy(&mut writer, &self.policy)?;
        writer.bytes(self.seed0.as_bytes());
        write_dag(&mut writer, &self.dag)?;
        write_sig_set(&mut writer, &self.guilty);
        write_prekeys(&mut writer, &self.prekeys);

        let peer_prekeys: Vec<_> = self.peer_prekeys.iter().collect();
        writer.list(&peer_prekeys, |writer, (peer, (generation, public))| {
            writer
                .bytes(peer.as_bytes())
                .u32(*generation)
                .bytes(public.as_bytes());
        });

        let send: Vec<_> = self.send.iter().collect();
        writer.list(&send, |writer, (peer, state)| {
            writer.bytes(peer.as_bytes());
            write_chan(writer, &state.chan);
        });

        let recv: Vec<_> = self.recv.iter().collect();
        writer.list(&recv, |writer, (peer, state)| {
            writer.bytes(peer.as_bytes()).bytes(state.eph.as_bytes());
            write_chan(writer, &state.chan.chan);
            let buffered: Vec<_> = state.chan.buffer.iter().collect();
            writer.list(&buffered, |writer, (sequence, payload)| {
                writer.u64(**sequence).bytes(payload);
            });
        });

        writer.u64(usize_to_u64(self.nodekeys.capacity)?);
        let keys: Vec<_> = self.nodekeys.keys.iter().collect();
        writer.list(&keys, |writer, (oid, key)| {
            writer.bytes(*oid).bytes(key.as_bytes());
        });
        writer.list(&self.nodekeys.order, |writer, oid| {
            writer.bytes(oid);
        });

        write_oid_set(&mut writer, &self.absorbed);
        write_oid_set(&mut writer, &self.missing);
        write_operations(&mut writer, &self.pending);
        write_operations(&mut writer, &self.open_accusations);

        let versions: Vec<_> = self.seen_versions.iter().collect();
        writer.list(&versions, |writer, (version, (nodes, root))| {
            writer.bytes(*version);
            write_oid_set(writer, nodes);
            writer.bytes(root);
        });
        writer.bytes(&self.last_version);
        let bytes = writer.finish();
        if bytes.len() > MAX_FIELD {
            return Err(Error::LimitExceeded(
                "participant state exceeds codec limit",
            ));
        }
        Ok(bytes)
    }

    /// Reconstructs participant state and rejects malformed or inconsistent input.
    #[doc(hidden)]
    pub fn import_persistence_state(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_FIELD {
            return Err(Error::LimitExceeded(
                "participant state exceeds codec limit",
            ));
        }
        let mut reader = Reader::new(bytes);
        let identity = SigSecret::from_seed(&reader.array::<32>()?);
        let ipk = SigPublic::from_bytes(reader.array::<32>()?);
        if identity.public() != ipk {
            return Err(invalid("state identity binding is invalid"));
        }
        let sid = reader.array::<32>()?;
        let policy = read_policy(&mut reader)?;
        let seed0 = Secret::from(reader.array::<KEY_LEN>()?);
        let dag = read_dag(&mut reader, &sid)?;
        let guilty = read_sig_set(&mut reader, MAX_RECIPIENTS)?;
        let prekeys = read_prekeys(&mut reader)?;
        let peer_prekeys = read_peer_prekeys(&mut reader, ipk)?;
        let send = read_send_channels(&mut reader, ipk)?;
        let recv = read_recv_channels(&mut reader, ipk)?;
        let nodekeys = read_nodekeys(&mut reader)?;
        let absorbed = read_oid_set(&mut reader, MAX_OPS)?;
        let missing = read_oid_set(&mut reader, MAX_OPS)?;
        let pending = read_operations(&mut reader, &sid, MAX_PENDING)?;
        let open_accusations = read_operations(&mut reader, &sid, MAX_PENDING)?;
        let (seen_versions, last_version) = read_versions(&mut reader)?;
        reader.finish()?;

        let mut cparents = BTreeMap::new();
        for (oid, operation) in dag.iter() {
            if let crate::op::Body::Contrib {
                cparents: parents, ..
            } = &operation.body
            {
                cparents.insert(*oid, parents.clone());
            }
        }

        let participant = Self {
            identity,
            ipk,
            sid,
            policy,
            seed0,
            dag,
            guilty,
            prekeys,
            peer_prekeys,
            send,
            recv,
            nodekeys,
            cparents,
            absorbed,
            missing,
            pending,
            open_accusations,
            seen_versions,
            last_version,
            authz: RefCell::new(BTreeMap::new()),
            derived: RefCell::new(None),
        };
        validate_participant(&participant)?;
        Ok(participant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn participant_state_roundtrips_canonically() {
        let (mut participant, _) = Participant::create(Policy::leaderless(2)).unwrap();
        participant.tick();
        participant.tick();
        let original = participant.export_persistence_state().unwrap();
        let restored = Participant::import_persistence_state(&original).unwrap();
        assert_eq!(restored.identity(), participant.identity());
        assert_eq!(restored.session_id(), participant.session_id());
        assert_eq!(restored.members(), participant.members());
        assert_eq!(restored.version(), participant.version());
        assert_eq!(restored.export_persistence_state().unwrap(), original);
    }

    #[test]
    fn participant_state_rejects_trailing_bytes_and_identity_substitution() {
        let (participant, _) = Participant::create(Policy::leaderless(2)).unwrap();
        let state = participant.export_persistence_state().unwrap();

        let mut trailing = state.clone();
        trailing.push(0);
        assert!(Participant::import_persistence_state(&trailing).is_err());

        let mut substituted = state;
        // The first TLV field is a 32-byte identity seed: tag + u32 length.
        substituted[5] ^= 1;
        assert!(Participant::import_persistence_state(&substituted).is_err());
    }
}
