// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Participant state machine.
use crate::channel::{Chan, RecvChan};
use crate::checkpoint::{
    media_context_id, Capabilities, CheckpointCertificate, CheckpointSignature, ProtocolProfile,
    ResumptionRecord,
};
use crate::dag::Dag;
use crate::error::{Error, Result};
use crate::keys::{commitment, frontier, group_key, node_key, version_of, NodeKeys, OVERLAP};
use crate::membership::{Membership, Policy};
use crate::op::{Body, Kind, Oid, Op, SessionId, MAX_RECIPIENTS};
use crate::wire::{Envelope, KeyPackage, Message, Outbound};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use cfr_crypto::{
    aead_open, aead_seal, hash, kdf, mac, random_secret, DhPublic, DhSecret, Secret, SigPublic,
    SigSecret, KEY_LEN,
};
use core::cell::RefCell;

use crate::prekey::PrekeyPool;

/// Width of the key confirmation beacon: eight bytes of version label followed
/// by a four byte tag.
pub const BEACON_LEN: usize = 12;

/// Ceiling on buffered operations whose dependencies have not arrived.
pub const MAX_PENDING: usize = 512;

/// Active-history size at which an application should prepare reinitialization.
pub const REINIT_RECOMMENDED_AT: usize = 1024;

/// Things worth telling the application about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The group key changed; media keys must be re-derived.
    KeyChanged {
        /// The new version label.
        version: [u8; 8],
    },
    /// A participant joined.
    Joined(SigPublic),
    /// A participant left or was evicted.
    Left(SigPublic),
    /// A participant was proven to have equivocated and is being evicted.
    Equivocation(SigPublic),
    /// The current version cannot be derived locally; repair is needed.
    RepairNeeded,
    /// A unanimous, locally verified offer to reinitialize into a new fresh session.
    CheckpointOffered(CheckpointCertificate),
}

/// Outcome of checking a peer's key confirmation beacon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Beacon {
    /// The peer holds the same version and the same key.
    Agreed,
    /// The peer holds a version this participant knows, but a different key.
    /// Someone is being fed a different history.
    Diverged,
    /// The peer's version is not one this participant has held. Usually just a
    /// lag; run anti-entropy before concluding anything.
    Unknown,
}

pub(crate) struct SendState {
    pub(crate) chan: Chan,
}

pub(crate) struct RecvState {
    pub(crate) eph: DhPublic,
    pub(crate) chan: RecvChan,
}

pub(crate) struct Derived {
    epoch: u64,
    guilty: usize,
    frontier: BTreeSet<Oid>,
    members: BTreeSet<SigPublic>,
    root: [u8; 32],
    version: [u8; 8],
}

/// Cache key for membership evaluated over one causal dependency set.
type AuthorizationCacheKey = ([u8; 32], u64, usize);
/// Memoized membership rosters keyed by causal past and derived-state epoch.
pub(crate) type AuthorizationCache = BTreeMap<AuthorizationCacheKey, BTreeSet<SigPublic>>;

/// A participant that has generated identity material but not yet joined.
pub struct PendingJoin {
    identity: SigSecret,
    prekeys: PrekeyPool,
    policy: Policy,
}

impl PendingJoin {
    /// Generates identity and prekey material for a newcomer.
    pub fn new(policy: Policy) -> Result<Self> {
        Ok(Self {
            identity: SigSecret::generate()?,
            prekeys: PrekeyPool::new()?,
            policy,
        })
    }

    /// The package to hand to an inviter out of band.
    pub fn key_package(&self) -> KeyPackage {
        let ipk = self.identity.public();
        let gen = self.prekeys.generation();
        let prekey = self.prekeys.public();
        let img = KeyPackage::image(&ipk, gen, &prekey);
        KeyPackage {
            ipk,
            gen,
            prekey,
            sig: self.identity.sign(&img),
        }
    }

    /// The identity this participant will use.
    pub fn identity(&self) -> SigPublic {
        self.identity.public()
    }

    /// Consumes a welcome and becomes a full participant.
    pub fn accept(mut self, wire: &[u8]) -> Result<(Participant, Vec<Outbound>)> {
        let Message::Welcome {
            sid,
            from,
            sealed,
            history,
            pruned: _,
        } = Message::from_wire(wire)?
        else {
            return Err(Error::Encoding("expected a welcome"));
        };

        // Authenticate the envelope before accepting its history.
        if sealed.gen != self.prekeys.generation() {
            return Err(Error::NoPrekey);
        }
        let ipk = self.identity.public();
        let shared = self
            .prekeys
            .agree_envelope(&sealed.eph)
            .ok_or(Error::NoPrekey)?;
        let k = envelope_key(&shared, &sid, &from, &ipk);
        let ad = hash(b"cfr/welcome/ad", &[&sid, from.as_bytes(), ipk.as_bytes()]);
        let n = cfr_crypto::nonce(&[&sid, sealed.eph.as_bytes(), b"welcome"]);
        let plain = aead_open(k.as_bytes(), &n, &sealed.ct, &ad).map_err(|_| Error::Decrypt)?;

        let (seed0, node_keys) = parse_welcome_payload(&plain)?;

        let mut p = Participant {
            identity: self.identity,
            ipk,
            sid,
            policy: self.policy,
            seed0,
            dag: Dag::new(),
            guilty: BTreeSet::new(),
            prekeys: self.prekeys,
            peer_prekeys: BTreeMap::new(),
            send: BTreeMap::new(),
            recv: BTreeMap::new(),
            nodekeys: NodeKeys::default(),
            cparents: BTreeMap::new(),
            absorbed: BTreeSet::new(),
            missing: BTreeSet::new(),
            pending: Vec::new(),
            open_accusations: Vec::new(),
            seen_versions: BTreeMap::new(),
            last_version: [0u8; 8],
            derived: RefCell::new(None),
            authz: RefCell::new(BTreeMap::new()),
        };

        for (oid, key) in node_keys {
            p.nodekeys.insert(oid, key);
            p.absorbed.insert(oid);
        }

        // A welcome is a delivery shortcut, not a validation bypass.
        for op in history {
            let _ = p.ingest(op)?;
        }
        p.rebuild_contribution_parents();

        if !p.members().contains(&p.ipk) {
            return Err(Error::NotParticipating);
        }

        // Announce the current prekey; defer contribution until peer prekey
        // rotations triggered by this admission have arrived.
        let out = alloc::vec![p.publish_prekeys()?];
        p.note_version();
        Ok((p, out))
    }
}

/// A conference participant.
pub struct Participant {
    pub(crate) identity: SigSecret,
    pub(crate) ipk: SigPublic,
    pub(crate) sid: SessionId,
    pub(crate) policy: Policy,
    pub(crate) seed0: Secret<KEY_LEN>,

    pub(crate) dag: Dag,
    pub(crate) guilty: BTreeSet<SigPublic>,

    pub(crate) prekeys: PrekeyPool,
    pub(crate) peer_prekeys: BTreeMap<SigPublic, (u32, DhPublic)>,
    pub(crate) send: BTreeMap<SigPublic, SendState>,
    pub(crate) recv: BTreeMap<SigPublic, RecvState>,

    pub(crate) nodekeys: NodeKeys,
    pub(crate) cparents: BTreeMap<Oid, BTreeSet<Oid>>,
    pub(crate) absorbed: BTreeSet<Oid>,
    pub(crate) missing: BTreeSet<Oid>,

    pub(crate) pending: Vec<Op>,
    pub(crate) open_accusations: Vec<Op>,

    pub(crate) seen_versions: BTreeMap<[u8; 8], (BTreeSet<Oid>, [u8; 32])>,
    pub(crate) last_version: [u8; 8],

    /// Memoized membership rosters for equivalent causal dependency sets.
    pub(crate) authz: RefCell<AuthorizationCache>,

    /// Graph-derived values, invalidated when graph or accusation state changes.
    pub(crate) derived: RefCell<Option<Derived>>,
}

impl Participant {
    // ---------------------------------------------------------------- setup

    /// Founds a conference.
    pub fn create(policy: Policy) -> Result<(Self, Vec<Outbound>)> {
        let identity = SigSecret::generate()?;
        let mut sid = [0u8; 32];
        cfr_crypto::fill_random(&mut sid)?;
        let seed0 = random_secret()?;
        let ipk = identity.public();

        let mut p = Self {
            identity,
            ipk,
            sid,
            policy,
            seed0,
            dag: Dag::new(),
            guilty: BTreeSet::new(),
            prekeys: PrekeyPool::new()?,
            peer_prekeys: BTreeMap::new(),
            send: BTreeMap::new(),
            recv: BTreeMap::new(),
            nodekeys: NodeKeys::default(),
            cparents: BTreeMap::new(),
            absorbed: BTreeSet::new(),
            missing: BTreeSet::new(),
            pending: Vec::new(),
            open_accusations: Vec::new(),
            seen_versions: BTreeMap::new(),
            last_version: [0u8; 8],
            derived: RefCell::new(None),
            authz: RefCell::new(BTreeMap::new()),
        };

        let mut out = Vec::new();
        let add = p.sign(Body::Add { who: ipk });
        p.dag.add(add.clone())?;
        out.push(Outbound::broadcast(&Message::Op(add)));
        out.push(p.publish_prekeys()?);
        out.extend(p.contribute()?);
        p.note_version();
        Ok((p, out))
    }

    // ------------------------------------------------------------ accessors

    /// This participant's identity.
    pub fn identity(&self) -> SigPublic {
        self.ipk
    }

    /// The conference identifier.
    pub fn session_id(&self) -> SessionId {
        self.sid
    }

    fn derived(&self) -> core::cell::Ref<'_, Derived> {
        let stale = {
            let cur = self.derived.borrow();
            match &*cur {
                Some(d) => d.epoch != self.dag.epoch() || d.guilty != self.guilty.len(),
                None => true,
            }
        };
        if stale {
            let frontier = frontier(&self.dag);
            let m = Membership::new(&self.dag, &self.policy, &self.guilty);
            let members = m.members();
            let root = Membership::root_for_members(&members);
            let version = version_of(&frontier, &root);
            *self.derived.borrow_mut() = Some(Derived {
                epoch: self.dag.epoch(),
                guilty: self.guilty.len(),
                frontier,
                members,
                root,
                version,
            });
        }
        core::cell::Ref::map(self.derived.borrow(), |d| {
            d.as_ref().expect("populated above")
        })
    }

    /// The current roster.
    pub fn members(&self) -> BTreeSet<SigPublic> {
        self.derived().members.clone()
    }

    /// The current version label. Always defined, even when the key itself
    /// cannot be derived yet.
    pub fn version(&self) -> [u8; 8] {
        self.derived().version
    }

    /// The current group key, if this participant holds the node keys for it.
    pub fn group_key(&self) -> Option<Secret<KEY_LEN>> {
        let d = self.derived();
        group_key(&self.seed0, &d.frontier, &d.root, &self.nodekeys)
    }

    /// Whether the current version can be derived locally.
    pub fn can_derive(&self) -> bool {
        self.group_key().is_some()
    }

    /// The contribution nodes at the tip of the graph.
    pub fn frontier(&self) -> BTreeSet<Oid> {
        self.derived().frontier.clone()
    }

    /// Number of operations retained.
    pub fn history_len(&self) -> usize {
        self.dag.len()
    }

    /// Approximate retained state in bytes, for capacity planning.
    pub fn state_bytes(&self) -> usize {
        let ops: usize = self.dag.iter().map(|(_, op)| op.wire_len()).sum();
        let edges: usize = self
            .dag
            .oids()
            .map(|o| 32 + 32 * self.dag.parents_of(o).map_or(0, BTreeSet::len))
            .sum();
        let keys = self.nodekeys.len() * 64;
        let chans = (self.send.len() + self.recv.len()) * 96;
        ops + edges + keys + chans + 256
    }

    /// Returns true when the application should prepare a signed reinitialization.
    pub fn reinitialization_recommended(&self) -> bool {
        self.history_len() >= REINIT_RECOMMENDED_AT
    }

    /// Prepares the record that active members must sign before a current reinitialization.
    ///
    /// The caller supplies a fresh random `next_session` and monotonically increases
    /// `checkpoint_epoch` per old session. This method never mutates local history.
    pub fn prepare_checkpoint(
        &self,
        next_session: SessionId,
        checkpoint_epoch: u64,
        profile: ProtocolProfile,
    ) -> Result<ResumptionRecord> {
        ResumptionRecord::new(
            self.sid,
            media_context_id(self.version()),
            self.frontier(),
            self.membership().root(),
            checkpoint_epoch,
            next_session,
            profile,
            Capabilities::CORE_SECURITY,
        )
    }

    /// Signs a state-bound checkpoint record on behalf of this active member.
    pub fn approve_checkpoint(&self, record: &ResumptionRecord) -> Result<CheckpointSignature> {
        self.validate_checkpoint_record(record)?;
        Ok(CheckpointSignature {
            signer: self.ipk,
            signature: self.identity.sign(&record.signing_bytes()),
        })
    }

    /// Validates and broadcasts a checkpoint offer without applying it locally.
    ///
    /// The application receives the same offer through [`Self::handle`] and must
    /// create a fresh session only after its own migration policy accepts it.
    pub fn offer_checkpoint(&self, certificate: &CheckpointCertificate) -> Result<Outbound> {
        self.validate_checkpoint(certificate)?;
        Ok(Outbound::broadcast(&Message::Checkpoint(
            certificate.clone(),
        )))
    }

    fn validate_checkpoint(&self, certificate: &CheckpointCertificate) -> Result<()> {
        let membership = self.membership();
        let roster = membership.members();
        certificate.verify(&roster)?;
        self.validate_checkpoint_record(certificate.record())
    }

    fn validate_checkpoint_record(&self, record: &ResumptionRecord) -> Result<()> {
        let membership = self.membership();
        if record.previous_session != self.sid
            || record.previous_context != media_context_id(self.version())
            || record.previous_frontier != self.frontier()
            || record.membership_root != membership.root()
        {
            return Err(Error::Unauthorised("checkpoint does not match local state"));
        }
        Ok(())
    }

    /// Authorisation with a memo over the operation's dependency set.
    fn authorised(&self, op: &Op) -> bool {
        let mut key_fields: Vec<&[u8]> = Vec::with_capacity(op.deps.len());
        for d in &op.deps {
            key_fields.push(d.as_slice());
        }
        let digest = hash(b"cfr/authz", &key_fields);
        let key = (digest, self.dag.epoch(), self.guilty.len());
        if let Some(past) = self.authz.borrow().get(&key) {
            return decide(op, past, &self.dag);
        }
        let past = self.membership().members_before(op);
        let verdict = decide(op, &past, &self.dag);
        let mut cache = self.authz.borrow_mut();
        if cache.len() > 4096 {
            cache.clear();
        }
        cache.insert(key, past);
        verdict
    }

    fn membership(&self) -> Membership<'_> {
        Membership::new(&self.dag, &self.policy, &self.guilty)
    }

    fn sign(&self, body: Body) -> Op {
        Op::create(&self.identity, &self.sid, self.dag.heads(), body)
    }

    // ------------------------------------------------------------- beacons

    /// A key confirmation beacon: the version label plus a tag over it.
    ///
    /// It costs twelve bytes and can ride along with media, which is what makes
    /// silent divergence detectable rather than theoretical. A participant fed
    /// a different history produces a tag that does not check.
    pub fn beacon(&self) -> [u8; BEACON_LEN] {
        let mut out = [0u8; BEACON_LEN];
        let v = self.version();
        out[..8].copy_from_slice(&v);
        if let Some(k) = self.group_key() {
            let t = mac(&k, b"cfr/confirm", &[&v, self.ipk.as_bytes()]);
            out[8..].copy_from_slice(&t[..4]);
        }
        out
    }

    /// Checks a peer's beacon against locally derivable keys.
    pub fn check_beacon(&self, peer: &SigPublic, beacon: &[u8; BEACON_LEN]) -> Beacon {
        let mut v = [0u8; 8];
        v.copy_from_slice(&beacon[..8]);
        let Some((nodes, root)) = self.seen_versions.get(&v) else {
            return Beacon::Unknown;
        };
        let Some(k) = group_key(&self.seed0, nodes, root, &self.nodekeys) else {
            return Beacon::Unknown;
        };
        // The wire format carries only a four-byte MAC prefix.
        let full = mac(&k, b"cfr/confirm", &[&v, peer.as_bytes()]);
        if cfr_crypto::ct_eq(&full[..4], &beacon[8..]) {
            Beacon::Agreed
        } else {
            Beacon::Diverged
        }
    }

    fn note_version(&mut self) {
        let (f, root, v) = {
            let d = self.derived();
            (d.frontier.clone(), d.root, d.version)
        };
        self.seen_versions.insert(v, (f, root));
        while self.seen_versions.len() > OVERLAP {
            let oldest = *self
                .seen_versions
                .keys()
                .next()
                .expect("non-empty by loop condition");
            self.seen_versions.remove(&oldest);
        }
        self.last_version = v;
    }

    // ------------------------------------------------------------ prekeys

    /// Publishes a fresh prekey generation. This is the healing step: after a
    /// compromise, rotating is what removes the attacker's read access.
    pub fn publish_prekeys(&mut self) -> Result<Outbound> {
        let op = self.sign(Body::Prekeys {
            gen: self.prekeys.generation(),
            pk: self.prekeys.public(),
        });
        self.dag.add(op.clone())?;
        Ok(Outbound::broadcast(&Message::Op(op)))
    }

    /// Destroys the current prekey generation and publishes a new one.
    pub fn rotate_prekeys(&mut self) -> Result<Outbound> {
        self.prekeys.rotate()?;
        self.publish_prekeys()
    }

    /// Advances deadline clocks. Call roughly once per rotation interval.
    pub fn tick(&mut self) {
        self.prekeys.tick();
    }

    // ------------------------------------------------------- contributions

    /// Contributes fresh entropy, moving the group key forward.
    pub fn contribute(&mut self) -> Result<Vec<Outbound>> {
        self.contribute_excluding(&BTreeSet::new())
    }

    /// Contributes while excluding selected recipients from the next key.
    ///
    /// A removal takes effect cryptographically only after such a contribution.
    pub fn contribute_excluding(&mut self, exclude: &BTreeSet<SigPublic>) -> Result<Vec<Outbound>> {
        let members = self.members();
        if !members.contains(&self.ipk) {
            return Err(Error::NotParticipating);
        }
        let recips: Vec<SigPublic> = members
            .iter()
            .filter(|m| **m != self.ipk && !exclude.contains(*m))
            .copied()
            .collect();
        if recips.len() > MAX_RECIPIENTS {
            return Err(Error::LimitExceeded("conference too large"));
        }

        // Request missing prekeys instead of silently excluding members.
        let unreachable: Vec<SigPublic> = recips
            .iter()
            .filter(|v| !self.send.contains_key(*v) && !self.peer_prekeys.contains_key(*v))
            .copied()
            .collect();
        if !unreachable.is_empty() {
            let op = self.sign(Body::PrekeyRequest {
                targets: unreachable,
            });
            self.dag.add(op.clone())?;
            return Ok(alloc::vec![Outbound::broadcast(&Message::Op(op))]);
        }

        let cparents = self.chainable_parents(&members);
        let view = self.derived().root;
        // Do not publish a frontier node whose key the author cannot derive.
        if !cparents.is_empty() && self.nodekeys.combine(&cparents).is_none() {
            return Err(Error::MissingNodeKeys);
        }

        let x = random_secret()?;
        let cid = commitment(&x);
        let ad = hash(b"cfr/contrib/ad", &[&cid, &view]);

        let mut slices = Vec::with_capacity(recips.len());
        for v in &recips {
            let establish = if self.send.contains_key(v) {
                None
            } else {
                let (gen, pk) = *self.peer_prekeys.get(v).ok_or(Error::NoPrekey)?;
                let eph = DhSecret::generate()?;
                let shared = eph.agree(&pk).ok_or(Error::NoPrekey)?;
                let root = channel_root(&shared, &self.sid, &self.ipk, v, gen);
                self.send.insert(
                    *v,
                    SendState {
                        chan: Chan::new(&kdf(&root, b"cfr/chan/data", &[])),
                    },
                );
                Some((gen, eph.public()))
            };
            let st = self.send.get_mut(v).expect("inserted above");
            let (seq, mk) = st.chan.step()?;
            let n = cfr_crypto::nonce(&[&self.sid, &cid, v.as_bytes(), &seq.to_be_bytes()]);
            let ct = aead_seal(mk.as_bytes(), &n, x.as_bytes(), &ad);
            slices.push(crate::op::Slice {
                to: *v,
                establish,
                seq,
                ct,
            });
        }

        let op = self.sign(Body::Contrib {
            cid,
            cparents,
            recips,
            slices,
            view,
        });
        self.dag.add(op.clone())?;
        self.absorb(&op, &x)?;
        self.note_version();
        Ok(alloc::vec![Outbound::broadcast(&Message::Op(op))])
    }

    /// Returns frontier nodes safe to chain into the next contribution.
    ///
    /// Derivable nodes are retained. An unavailable node is omitted only when
    /// its author is no longer a member, preventing a permanently underivable
    /// frontier. The signed parent set exposes this exceptional choice; an
    /// honest later contribution restores the full frontier.
    fn chainable_parents(&self, members: &BTreeSet<SigPublic>) -> BTreeSet<Oid> {
        self.frontier()
            .into_iter()
            .filter(|f| {
                if self.nodekeys.contains(f) {
                    return true;
                }
                let Some(op) = self.dag.get(f) else {
                    return true;
                };
                members.contains(&op.author)
            })
            .collect()
    }

    /// Returns the contribution frontier in `op`'s causal past for auditing.
    pub fn past_frontier(&self, op: &Op) -> BTreeSet<Oid> {
        let mut past: BTreeSet<Oid> = BTreeSet::new();
        for d in &op.deps {
            if self.dag.contains(d) {
                past.insert(*d);
                past.extend(self.dag.ancestors(d));
            }
        }
        let nodes: Vec<Oid> = past
            .iter()
            .filter(|o| self.dag.get(o).is_some_and(|x| x.kind() == Kind::Contrib))
            .copied()
            .collect();
        let mut covered: BTreeSet<Oid> = BTreeSet::new();
        for n in &nodes {
            covered.extend(self.dag.ancestors(n));
        }
        nodes.into_iter().filter(|n| !covered.contains(n)).collect()
    }

    fn absorb(&mut self, op: &Op, x: &Secret<KEY_LEN>) -> Result<()> {
        let Body::Contrib { cid, cparents, .. } = &op.body else {
            return Err(Error::Internal(alloc::string::String::from(
                "absorb called on a non-contribution",
            )));
        };
        let oid = op.oid();
        if self.absorbed.contains(&oid) {
            return Ok(());
        }
        if &commitment(x) != cid {
            return Err(Error::Equivocation);
        }
        let parent = if cparents.is_empty() {
            Secret::<KEY_LEN>::zero()
        } else if let Some(p) = self.nodekeys.combine(cparents) {
            p
        } else {
            self.missing.insert(oid);
            return Err(Error::MissingNodeKeys);
        };
        self.nodekeys.insert(oid, node_key(x, &parent, &oid));
        self.cparents.insert(oid, cparents.clone());
        self.absorbed.insert(oid);
        self.missing.remove(&oid);
        Ok(())
    }

    fn rebuild_contribution_parents(&mut self) {
        let pairs: Vec<(Oid, BTreeSet<Oid>)> = self
            .dag
            .iter()
            .filter_map(|(oid, op)| match &op.body {
                Body::Contrib { cparents, .. } => Some((*oid, cparents.clone())),
                _ => None,
            })
            .collect();
        for (oid, cp) in pairs {
            self.cparents.insert(oid, cp);
        }
    }

    // ----------------------------------------------------------- membership

    /// Admits a newcomer and produces the sealed welcome.
    pub fn invite(&mut self, kp: &KeyPackage) -> Result<Vec<Outbound>> {
        kp.verify()?;
        if !self.members().contains(&self.ipk) {
            return Err(Error::NotParticipating);
        }
        self.peer_prekeys.insert(kp.ipk, (kp.gen, kp.prekey));

        let add = self.sign(Body::Add { who: kp.ipk });
        self.dag.add(add.clone())?;

        // Rotate a sealed generation before creating the welcome.
        let rotation = if self.prekeys.is_sealed() {
            Some(self.rotate_prekeys()?)
        } else {
            None
        };

        // Share only current-frontier node keys; older keys remain unavailable.
        let f = self.frontier();
        let mut entries: Vec<(Oid, Secret<KEY_LEN>)> = Vec::new();
        for n in &f {
            let Some(k) = self.nodekeys.peek(n) else {
                return Err(Error::MissingNodeKeys);
            };
            entries.push((*n, k.clone()));
        }
        let payload = build_welcome_payload(&self.seed0, &entries);

        let eph = DhSecret::generate()?;
        let shared = eph.agree(&kp.prekey).ok_or(Error::NoPrekey)?;
        let k = envelope_key(&shared, &self.sid, &self.ipk, &kp.ipk);
        let ad = hash(
            b"cfr/welcome/ad",
            &[&self.sid, self.ipk.as_bytes(), kp.ipk.as_bytes()],
        );
        let n = cfr_crypto::nonce(&[&self.sid, eph.public().as_bytes(), b"welcome"]);
        let ct = aead_seal(k.as_bytes(), &n, &payload, &ad);

        let history: Vec<Op> = self
            .dag
            .topological()
            .into_iter()
            .filter_map(|o| self.dag.get(&o).cloned())
            .collect();

        let welcome = Message::Welcome {
            pruned: Vec::new(),
            sid: self.sid,
            from: self.ipk,
            sealed: Envelope {
                eph: eph.public(),
                gen: kp.gen,
                ct,
            },
            history,
        };

        let mut out = alloc::vec![Outbound::broadcast(&Message::Op(add))];
        out.extend(rotation);
        out.push(Outbound::direct(kp.ipk, &welcome));
        out.extend(self.contribute()?);
        self.note_version();
        Ok(out)
    }

    /// Publishes an eviction and immediately rekeys without the evicted party.
    pub fn remove(&mut self, who: &SigPublic) -> Result<Vec<Outbound>> {
        let op = self.sign(Body::Remove { who: *who });
        self.dag.add(op.clone())?;
        let mut out = alloc::vec![Outbound::broadcast(&Message::Op(op))];
        let exclude: BTreeSet<SigPublic> = [*who].into_iter().collect();
        out.extend(self.contribute_excluding(&exclude)?);
        self.send.remove(who);
        self.recv.remove(who);
        self.note_version();
        Ok(out)
    }

    /// Leaves the conference.
    pub fn leave(&mut self) -> Result<Outbound> {
        let op = self.sign(Body::Remove { who: self.ipk });
        self.dag.add(op.clone())?;
        Ok(Outbound::broadcast(&Message::Op(op)))
    }

    /// Whether a removal has taken effect: some node in the current frontier
    /// was created after the eviction, does not address the evicted party, and
    /// was not authored by it.
    ///
    /// The authorship check prevents an evicted participant extending access
    /// through its own final contribution.
    pub fn removal_complete(&self, who: &SigPublic) -> bool {
        let removals: Vec<Oid> = self
            .dag
            .iter()
            .filter(|(_, op)| match &op.body {
                Body::Remove { who: w } => w == who,
                Body::Accuse { who: w, .. } => w == who && self.guilty.contains(who),
                _ => false,
            })
            .map(|(oid, _)| *oid)
            .collect();
        if removals.is_empty() {
            return false;
        }
        self.frontier().iter().any(|f| {
            let Some(op) = self.dag.get(f) else {
                return false;
            };
            let Body::Contrib { recips, .. } = &op.body else {
                return false;
            };
            if recips.contains(who) || &op.author == who {
                return false;
            }
            removals.iter().any(|r| self.dag.precedes(r, f))
        })
    }

    // -------------------------------------------------------------- inbound

    /// Processes one received message.
    pub fn handle(&mut self, wire: &[u8]) -> Result<(Vec<Event>, Vec<Outbound>)> {
        let msg = Message::from_wire(wire)?;
        let mut events = Vec::new();
        let mut out = Vec::new();
        let before = self.version();
        let members_before = self.members();

        match msg {
            Message::Op(op) => {
                out.extend(self.ingest(op)?);
            }
            Message::Deliver { ops, pruned: _ } => {
                for op in ops {
                    // Invalid operations do not discard valid batch entries.
                    if let Ok(o) = self.ingest(op) {
                        out.extend(o);
                    }
                }
            }
            Message::Sync { from, heads } => {
                // Serve history only to the current requesting member. A valid
                // head proves possession of its complete signed causal past.
                if self.members().contains(&from) {
                    let peer_has_unknown_head = heads.iter().any(|head| !self.dag.contains(head));
                    let known = self.dag.causal_closure(heads);
                    let ops: Vec<Op> = self
                        .dag
                        .topological()
                        .into_iter()
                        .filter(|oid| !known.contains(oid))
                        .filter_map(|oid| self.dag.get(&oid).cloned())
                        .collect();
                    if !ops.is_empty() {
                        out.push(Outbound::direct(
                            from,
                            &Message::Deliver {
                                ops,
                                pruned: Vec::new(),
                            },
                        ));
                    }
                    // An unknown peer head means this participant lacks part of
                    // the peer's graph. Request the peer's causal closure in the
                    // reverse direction; duplicate requests remain idempotent.
                    if peer_has_unknown_head {
                        out.push(Outbound::direct(
                            from,
                            &Message::Sync {
                                from: self.ipk,
                                heads: self.dag.heads().into_iter().collect(),
                            },
                        ));
                    }
                }
            }
            Message::NodeKeyRequest { from, nodes } => {
                if let Some(o) = self.answer_node_keys_for(&from, &nodes)? {
                    out.push(o);
                }
            }
            Message::NodeKeyResponse { from, sealed } => {
                self.absorb_node_keys(&from, &sealed)?;
            }
            Message::Checkpoint(certificate) => {
                self.validate_checkpoint(&certificate)?;
                events.push(Event::CheckpointOffered(certificate));
            }
            Message::Welcome { .. } => {
                return Err(Error::Encoding("welcome sent to an existing participant"));
            }
        }

        out.extend(self.drain_pending());

        let members_after = self.members();
        for m in members_after.difference(&members_before) {
            events.push(Event::Joined(*m));
        }
        for m in members_before.difference(&members_after) {
            events.push(Event::Left(*m));
        }
        let after = self.version();
        if after != before {
            self.note_version();
            events.push(Event::KeyChanged { version: after });
        }
        if !self.can_derive() {
            events.push(Event::RepairNeeded);
        }
        Ok((events, out))
    }

    /// Validates and applies one operation.
    fn ingest(&mut self, op: Op) -> Result<Vec<Outbound>> {
        // Authenticate the operation before inspecting its identity or effects.
        if op.sid != self.sid {
            return Err(Error::Encoding("operation from another conference"));
        }
        op.verify()?;

        let oid = op.oid();
        if self.dag.contains(&oid) {
            // Duplicate operations are idempotent no-ops.
            return Ok(Vec::new());
        }
        if !self.deps_available(&op) {
            if self.pending.len() < MAX_PENDING && !self.pending.contains(&op) {
                self.pending.push(op);
            }
            return Ok(Vec::new());
        }
        if !self.authorised(&op) {
            return Err(Error::NotAMember);
        }

        self.dag.add(op.clone())?;
        let mut out = Vec::new();
        match &op.body {
            Body::Prekeys { gen, pk } => {
                match self.peer_prekeys.get(&op.author) {
                    None => {
                        self.peer_prekeys.insert(op.author, (*gen, *pk));
                    }
                    Some((known, _)) if gen > known => {
                        self.peer_prekeys.insert(op.author, (*gen, *pk));
                        // Only a strictly newer prekey retires an established channel.
                        self.send.remove(&op.author);
                    }
                    Some(_) => {}
                }
            }
            Body::Contrib { .. } => {
                out.extend(self.receive_contribution(&op)?);
            }
            Body::Accuse { .. } => {
                if self.check_accusation(&op) {
                    if let Body::Accuse { who, .. } = &op.body {
                        self.guilty.insert(*who);
                    }
                }
            }
            Body::PrekeyRequest { targets } => {
                if targets.contains(&self.ipk) {
                    out.push(self.rotate_prekeys()?);
                }
            }
            Body::Add { who } => {
                // A new member requires a non-retired local prekey.
                if who != &self.ipk && self.prekeys.is_sealed() {
                    out.push(self.rotate_prekeys()?);
                }
            }
            Body::Remove { .. } => {}
        }
        self.retry_accusations();
        Ok(out)
    }

    fn receive_contribution(&mut self, op: &Op) -> Result<Vec<Outbound>> {
        let mut out = Vec::new();
        let Body::Contrib {
            cid, view, slices, ..
        } = &op.body
        else {
            return Ok(out);
        };
        let Some(slice) = slices.iter().find(|s| s.to == self.ipk).cloned() else {
            // Not addressed to us. Either we are the author, or this
            // contribution deliberately excludes us.
            return Ok(out);
        };
        let cid = *cid;
        let view = *view;

        if let Some((gen, eph)) = slice.establish {
            let needs_new = self.recv.get(&op.author).is_none_or(|r| r.eph != eph);
            if needs_new {
                if gen != self.prekeys.generation() {
                    // A retired prekey cannot open this slice; repair recovers it.
                    self.missing.insert(op.oid());
                    if gen < self.prekeys.generation() {
                        return Ok(out);
                    }
                    return Ok(out);
                }
                let expected: BTreeSet<SigPublic> = self
                    .members()
                    .into_iter()
                    .filter(|m| *m != self.ipk)
                    .collect();
                let Some(shared) = self.prekeys.agree_for(&op.author, &eph, &expected) else {
                    self.missing.insert(op.oid());
                    out.push(self.rotate_prekeys()?);
                    return Ok(out);
                };
                let root = channel_root(&shared, &self.sid, &op.author, &self.ipk, gen);
                self.recv.insert(
                    op.author,
                    RecvState {
                        eph,
                        chan: RecvChan::new(&kdf(&root, b"cfr/chan/data", &[])),
                    },
                );
            }
        }

        let ad = hash(b"cfr/contrib/ad", &[&cid, &view]);
        let mut payload = Vec::with_capacity(32 + slice.ct.len());
        payload.extend_from_slice(&op.oid());
        payload.extend_from_slice(&slice.ct);

        let Some(message_key) = self
            .recv
            .get_mut(&op.author)
            .and_then(|state| state.chan.offer(slice.seq, &payload))
        else {
            // Future slices are buffered; replays are ignored.
            return Ok(out);
        };
        if !self.open_slice(op, &message_key, slice.seq, &ad)? {
            // Keep the ratchet position for an authenticated retransmission.
            return Ok(out);
        }
        if let Some(state) = self.recv.get_mut(&op.author) {
            if !state.chan.commit(slice.seq)? {
                return Err(Error::Internal(
                    "channel position changed before commit".into(),
                ));
            }
        }

        // Drain newly contiguous buffered slices after successful authentication.
        loop {
            let Some((sequence, payload, message_key)) = self
                .recv
                .get_mut(&op.author)
                .and_then(|state| state.chan.take_next())
            else {
                break;
            };
            let (oid_bytes, _) = payload.split_at(32);
            let oid: Oid = oid_bytes.try_into().expect("32 byte prefix");
            let Some(buffered) = self.dag.get(&oid).cloned() else {
                self.missing.insert(oid);
                break;
            };
            let Body::Contrib { cid, view, .. } = &buffered.body else {
                self.missing.insert(oid);
                break;
            };
            let ad = hash(b"cfr/contrib/ad", &[cid, view]);
            if !self.open_slice(&buffered, &message_key, sequence, &ad)? {
                break;
            }
            let Some(state) = self.recv.get_mut(&op.author) else {
                break;
            };
            if !state.chan.commit(sequence)? {
                break;
            }
        }
        Ok(out)
    }

    /// Opens one contribution slice and reports AEAD authentication.
    ///
    /// Authenticated equivocation consumes the step after evidence is recorded;
    /// a bad tag leaves the sequence available for retransmission.
    fn open_slice(
        &mut self,
        op: &Op,
        mk: &Secret<KEY_LEN>,
        seq: u64,
        ad: &[u8; 32],
    ) -> Result<bool> {
        let Body::Contrib { cid, slices, .. } = &op.body else {
            return Ok(false);
        };
        let Some(slice) = slices.iter().find(|slice| slice.to == self.ipk) else {
            return Ok(false);
        };
        let n = cfr_crypto::nonce(&[
            &self.sid,
            cid.as_slice(),
            self.ipk.as_bytes(),
            &seq.to_be_bytes(),
        ]);
        let opened = aead_open(mk.as_bytes(), &n, &slice.ct, ad);
        let Ok(raw) = opened else {
            self.missing.insert(op.oid());
            return Ok(false);
        };
        let Some(x) = Secret::<KEY_LEN>::from_slice(&raw) else {
            self.missing.insert(op.oid());
            return Ok(false);
        };
        match self.absorb(op, &x) {
            Ok(()) | Err(Error::MissingNodeKeys) => Ok(true),
            Err(Error::Equivocation) => {
                // Publish transferable proof using the discarded one-time key.
                let acc = self.sign(Body::Accuse {
                    who: op.author,
                    coid: op.oid(),
                    mk: *mk.as_bytes(),
                    seq,
                });
                if self.check_accusation(&acc) {
                    self.guilty.insert(op.author);
                }
                self.dag.add(acc)?;
                Ok(true)
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn check_accusation(&self, acc: &Op) -> bool {
        let Body::Accuse { who, coid, mk, seq } = &acc.body else {
            return false;
        };
        let Some(src) = self.dag.get(coid) else {
            return false;
        };
        if src.kind() != Kind::Contrib || &src.author != who {
            return false;
        }
        let Body::Contrib {
            cid, slices, view, ..
        } = &src.body
        else {
            return false;
        };
        let Some(slice) = slices.iter().find(|s| s.to == acc.author) else {
            return false;
        };
        let ad = hash(b"cfr/contrib/ad", &[cid, view]);
        let n = cfr_crypto::nonce(&[
            &self.sid,
            cid.as_slice(),
            acc.author.as_bytes(),
            &seq.to_be_bytes(),
        ]);
        let key = Secret::<KEY_LEN>::new(*mk);
        let Ok(raw) = aead_open(key.as_bytes(), &n, &slice.ct, &ad) else {
            // The revealed key does not open the slice, so the accusation
            // proves nothing. A false accusation costs the accuser its own
            // one-time key and gains it nothing.
            return false;
        };
        let Some(x) = Secret::<KEY_LEN>::from_slice(&raw) else {
            return false;
        };
        &commitment(&x) != cid
    }

    fn retry_accusations(&mut self) {
        let parked = core::mem::take(&mut self.open_accusations);
        for acc in parked {
            if self.check_accusation(&acc) {
                if let Body::Accuse { who, .. } = &acc.body {
                    self.guilty.insert(*who);
                }
            } else if self
                .dag
                .get(match &acc.body {
                    Body::Accuse { coid, .. } => coid,
                    _ => &[0u8; 32],
                })
                .is_none()
            {
                self.open_accusations.push(acc);
            }
        }
    }

    /// Whether every signed dependency is present in the local graph.
    fn deps_available(&self, op: &Op) -> bool {
        op.deps
            .iter()
            .all(|dependency| self.dag.contains(dependency))
    }

    fn drain_pending(&mut self) -> Vec<Outbound> {
        let mut out = Vec::new();
        let mut waiting = core::mem::take(&mut self.pending);

        loop {
            let mut deferred = Vec::with_capacity(waiting.len());
            let mut progressed = false;
            for op in waiting.drain(..) {
                if !self.deps_available(&op) {
                    deferred.push(op);
                    continue;
                }
                // Ready invalid operations cannot become valid after another delivery.
                if let Ok(outbound) = self.ingest(op) {
                    out.extend(outbound);
                    progressed = true;
                }
            }
            if !progressed {
                self.pending = deferred;
                break;
            }
            waiting = deferred;
        }
        out
    }

    // --------------------------------------------------------------- repair

    /// Asks the conference for operations this participant may be missing.
    pub fn sync_request(&self) -> Outbound {
        // A head implies all of its signed ancestors, so a compact frontier
        // summary is sufficient for exact reconciliation on a causal DAG.
        let heads: Vec<Oid> = self.dag.heads().into_iter().collect();
        Outbound::broadcast(&Message::Sync {
            from: self.ipk,
            heads,
        })
    }

    /// Asks for node keys this participant cannot derive.
    ///
    /// Returns `None` when nothing is missing. The request names only nodes in
    /// the participant's own frontier: asking for older material would widen
    /// the overlap window and weaken condition (S3).
    pub fn repair_request(&mut self) -> Option<Vec<Outbound>> {
        let nodes = self.nodekeys.missing(self.frontier().iter());
        if nodes.is_empty() {
            return None;
        }
        let mut out = Vec::new();
        // The response comes back sealed to our published prekey, so a retired
        // generation would make the repair unreadable. Refresh first.
        if self.prekeys.is_sealed() {
            out.push(self.rotate_prekeys().ok()?);
        }
        out.push(Outbound::broadcast(&Message::NodeKeyRequest {
            from: self.ipk,
            nodes: nodes.into_iter().collect(),
        }));
        Some(out)
    }

    /// Whether any node key needed for the current version is absent.
    pub fn needs_repair(&self) -> bool {
        !self.nodekeys.missing(self.frontier().iter()).is_empty()
    }

    fn answer_node_keys_for(&mut self, to: &SigPublic, nodes: &[Oid]) -> Result<Option<Outbound>> {
        if !self.members().contains(to) {
            return Ok(None);
        }
        // Serve current members only and only for the current frontier. This
        // restores the current key without exposing pre-admission history.
        let frontier_now = self.frontier();
        let mut entries: Vec<(Oid, Secret<KEY_LEN>)> = Vec::new();
        for n in nodes {
            if !frontier_now.contains(n) {
                continue;
            }
            if let Some(k) = self.nodekeys.peek(n) {
                entries.push((*n, k.clone()));
            }
        }
        if entries.is_empty() {
            return Ok(None);
        }
        let (gen, pk) = *self.peer_prekeys.get(to).ok_or(Error::NoPrekey)?;
        let eph = DhSecret::generate()?;
        let shared = eph.agree(&pk).ok_or(Error::NoPrekey)?;
        let k = envelope_key(&shared, &self.sid, &self.ipk, to);
        let ad = hash(
            b"cfr/repair/ad",
            &[&self.sid, self.ipk.as_bytes(), to.as_bytes()],
        );
        let n = cfr_crypto::nonce(&[&self.sid, eph.public().as_bytes(), b"repair"]);
        let payload = build_nodekey_payload(&entries);
        let ct = aead_seal(k.as_bytes(), &n, &payload, &ad);
        Ok(Some(Outbound::direct(
            *to,
            &Message::NodeKeyResponse {
                from: self.ipk,
                sealed: Envelope {
                    eph: eph.public(),
                    gen,
                    ct,
                },
            },
        )))
    }

    fn absorb_node_keys(&mut self, from: &SigPublic, sealed: &Envelope) -> Result<()> {
        if !self.members().contains(from) {
            return Err(Error::NotAMember);
        }
        if sealed.gen != self.prekeys.generation() {
            return Err(Error::NoPrekey);
        }
        let shared = self
            .prekeys
            .agree_envelope(&sealed.eph)
            .ok_or(Error::NoPrekey)?;
        let k = envelope_key(&shared, &self.sid, from, &self.ipk);
        let ad = hash(
            b"cfr/repair/ad",
            &[&self.sid, from.as_bytes(), self.ipk.as_bytes()],
        );
        let n = cfr_crypto::nonce(&[&self.sid, sealed.eph.as_bytes(), b"repair"]);
        let plain = aead_open(k.as_bytes(), &n, &sealed.ct, &ad).map_err(|_| Error::Decrypt)?;
        let want = self.frontier();
        for (oid, key) in parse_nodekey_payload(&plain)? {
            // Retain only node keys required by the current frontier.
            if !want.contains(&oid) {
                continue;
            }
            self.nodekeys.insert(oid, key);
            self.absorbed.insert(oid);
            self.missing.remove(&oid);
        }
        Ok(())
    }

    /// Documents the current history boundary.
    ///
    /// Signed dependencies remain part of authorization in the active session.
    /// CFR therefore bounds active history only by unanimous signed
    /// reinitialization into a fresh session; it never trusts remote pruned IDs
    /// or silently rewrites the local DAG.
    pub fn history_note() {}
}

/// Applies authorization to a roster already derived from causal history.
fn decide(op: &Op, past: &BTreeSet<SigPublic>, dag: &Dag) -> bool {
    if op.kind() == Kind::Add {
        if past.contains(&op.author) {
            return true;
        }
        let Body::Add { who } = &op.body else {
            return false;
        };
        who == &op.author
            && op.deps.is_empty()
            && !dag.iter().any(|(_, o)| {
                matches!(o.kind(), Kind::Add)
                    && o.deps.is_empty()
                    && matches!(&o.body, Body::Add { who: w } if w == &o.author)
                    && o.author != op.author
            })
    } else {
        if let Body::Remove { who } = &op.body {
            if who == &op.author {
                return true;
            }
        }
        past.contains(&op.author)
    }
}

// ------------------------------------------------------------------ helpers

fn channel_root(
    shared: &Secret<KEY_LEN>,
    sid: &SessionId,
    from: &SigPublic,
    to: &SigPublic,
    gen: u32,
) -> Secret<KEY_LEN> {
    kdf(
        shared,
        b"cfr/root",
        &[sid, from.as_bytes(), to.as_bytes(), &gen.to_be_bytes()],
    )
}

fn envelope_key(
    shared: &Secret<KEY_LEN>,
    sid: &SessionId,
    from: &SigPublic,
    to: &SigPublic,
) -> Secret<KEY_LEN> {
    kdf(
        shared,
        b"cfr/envelope",
        &[sid, from.as_bytes(), to.as_bytes()],
    )
}

fn build_welcome_payload(seed0: &Secret<KEY_LEN>, entries: &[(Oid, Secret<KEY_LEN>)]) -> Vec<u8> {
    let mut w = crate::codec::Writer::new();
    w.bytes(seed0.as_bytes());
    w.list(entries, |w, (oid, k)| {
        w.bytes(oid).bytes(k.as_bytes());
    });
    w.finish()
}

fn parse_welcome_payload(buf: &[u8]) -> Result<(Secret<KEY_LEN>, Vec<(Oid, Secret<KEY_LEN>)>)> {
    let mut r = crate::codec::Reader::new(buf);
    let seed0 = Secret::new(r.array::<32>()?);
    let entries = r.list(|r| Ok((r.array::<32>()?, Secret::new(r.array::<32>()?))))?;
    r.finish()?;
    Ok((seed0, entries))
}

fn build_nodekey_payload(entries: &[(Oid, Secret<KEY_LEN>)]) -> Vec<u8> {
    let mut w = crate::codec::Writer::new();
    w.list(entries, |w, (oid, k)| {
        w.bytes(oid).bytes(k.as_bytes());
    });
    w.finish()
}

fn parse_nodekey_payload(buf: &[u8]) -> Result<Vec<(Oid, Secret<KEY_LEN>)>> {
    let mut r = crate::codec::Reader::new(buf);
    let entries = r.list(|r| Ok((r.array::<32>()?, Secret::new(r.array::<32>()?))))?;
    r.finish()?;
    Ok(entries)
}
