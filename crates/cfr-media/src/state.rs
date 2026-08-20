// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Private, bounded media-state codec used by the application crate.

use crate::error::{Error, Result};
use crate::frame::{context_id, sender_tag, ContextId, Protector, SenderTag, VersionKeys};
use crate::ratchet::{RecvRatchet, SendRatchet, EPOCH};
use crate::replay::Replay;
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;
use cfr_crypto::{Secret, SigPublic, KEY_LEN};

const MAX_MEDIA_STATE_BYTES: usize = 1 << 22;
const MAX_RETAINED_VERSIONS: usize = 64;
const MAX_ROSTER: usize = 256;

#[derive(Default)]
struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn fixed(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    fn count(&mut self, value: usize) -> Result<()> {
        self.u32(u32::try_from(value).map_err(|_| Error::MalformedState)?);
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() > MAX_MEDIA_STATE_BYTES {
            return Err(Error::MalformedState);
        }
        Ok(Self { bytes, position: 0 })
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(Error::MalformedState)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(Error::MalformedState)?;
        self.position = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error::MalformedState)
    }

    fn u8(&mut self) -> Result<u8> {
        self.take(1)?.first().copied().ok_or(Error::MalformedState)
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn count(&mut self, limit: usize) -> Result<usize> {
        let value = usize::try_from(self.u32()?).map_err(|_| Error::MalformedState)?;
        if value > limit {
            return Err(Error::MalformedState);
        }
        Ok(value)
    }

    fn finish(self) -> Result<()> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::MalformedState)
        }
    }
}

fn read_bool(reader: &mut Reader<'_>) -> Result<bool> {
    match reader.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error::MalformedState),
    }
}

fn expected_send_epoch(counter: u64) -> u64 {
    counter.saturating_sub(1) / EPOCH
}

fn read_roster(reader: &mut Reader<'_>) -> Result<BTreeMap<SenderTag, SigPublic>> {
    let count = reader.count(MAX_ROSTER)?;
    let mut roster = BTreeMap::new();
    let mut previous = None;
    for _ in 0..count {
        let tag = reader.array::<8>()?;
        if previous.is_some_and(|value| value >= tag) {
            return Err(Error::MalformedState);
        }
        previous = Some(tag);
        let identity = SigPublic::from_bytes(reader.array::<32>()?);
        if sender_tag(&identity) != tag {
            return Err(Error::MalformedState);
        }
        roster.insert(tag, identity);
    }
    Ok(roster)
}

fn read_receivers(
    reader: &mut Reader<'_>,
    roster: &BTreeMap<SenderTag, SigPublic>,
    my_tag: SenderTag,
) -> Result<BTreeMap<SenderTag, (RecvRatchet, Replay)>> {
    let count = reader.count(roster.len())?;
    let mut receivers = BTreeMap::new();
    let mut previous = None;
    for _ in 0..count {
        let tag = reader.array::<8>()?;
        if previous.is_some_and(|value| value >= tag) || tag == my_tag || !roster.contains_key(&tag)
        {
            return Err(Error::MalformedState);
        }
        previous = Some(tag);
        let ratchet = RecvRatchet {
            chain: Secret::from(reader.array::<KEY_LEN>()?),
            epoch: reader.u64()?,
        };
        let replay = Replay {
            high: reader.u64()?,
            seen: reader.u64()?,
            started: read_bool(reader)?,
        };
        if (!replay.started && (replay.high != 0 || replay.seen != 0))
            || (replay.started && (replay.seen & 1 == 0 || ratchet.epoch != replay.high / EPOCH))
        {
            return Err(Error::MalformedState);
        }
        receivers.insert(tag, (ratchet, replay));
    }
    Ok(receivers)
}

fn read_version(
    reader: &mut Reader<'_>,
    context: ContextId,
    my_tag: SenderTag,
) -> Result<VersionKeys> {
    let version = reader.array::<8>()?;
    if context_id(version) != context {
        return Err(Error::MalformedState);
    }
    let key = Secret::from(reader.array::<KEY_LEN>()?);
    let roster = read_roster(reader)?;
    let send = SendRatchet {
        chain: Secret::from(reader.array::<KEY_LEN>()?),
        epoch: reader.u64()?,
    };
    let recv = read_receivers(reader, &roster, my_tag)?;
    let counter = reader.u64()?;
    if send.epoch != expected_send_epoch(counter) {
        return Err(Error::MalformedState);
    }
    Ok(VersionKeys {
        version,
        key,
        roster,
        send,
        recv,
        counter,
    })
}

fn read_order(
    reader: &mut Reader<'_>,
    versions: &BTreeMap<ContextId, VersionKeys>,
    retain: usize,
) -> Result<VecDeque<ContextId>> {
    let count = reader.count(retain)?;
    if count != versions.len() {
        return Err(Error::MalformedState);
    }
    let mut order = VecDeque::with_capacity(count);
    let mut unique = BTreeSet::new();
    for _ in 0..count {
        let context = reader.array::<16>()?;
        if !versions.contains_key(&context) || !unique.insert(context) {
            return Err(Error::MalformedState);
        }
        order.push_back(context);
    }
    Ok(order)
}

impl Protector {
    /// Encodes all media ratchets, counters, and replay windows.
    #[doc(hidden)]
    pub fn export_persistence_state(&self) -> Result<Vec<u8>> {
        let mut writer = Writer::default();
        writer.fixed(&self.sid);
        writer.fixed(self.me.as_bytes());
        writer.fixed(&self.my_tag);
        writer.count(self.retain)?;
        writer.count(self.versions.len())?;
        for (context, version) in &self.versions {
            writer.fixed(context);
            writer.fixed(&version.version);
            writer.fixed(version.key.as_bytes());
            writer.count(version.roster.len())?;
            for (tag, identity) in &version.roster {
                writer.fixed(tag);
                writer.fixed(identity.as_bytes());
            }
            writer.fixed(version.send.chain.as_bytes());
            writer.u64(version.send.epoch);
            writer.count(version.recv.len())?;
            for (tag, (ratchet, replay)) in &version.recv {
                writer.fixed(tag);
                writer.fixed(ratchet.chain.as_bytes());
                writer.u64(ratchet.epoch);
                writer.u64(replay.high);
                writer.u64(replay.seen);
                writer.u8(u8::from(replay.started));
            }
            writer.u64(version.counter);
        }
        writer.count(self.order.len())?;
        for context in &self.order {
            writer.fixed(context);
        }
        match self.current {
            Some(context) => {
                writer.u8(1);
                writer.fixed(&context);
            }
            None => writer.u8(0),
        }
        let bytes = writer.finish();
        if bytes.len() > MAX_MEDIA_STATE_BYTES {
            return Err(Error::MalformedState);
        }
        Ok(bytes)
    }

    /// Reconstructs media state and rejects malformed or inconsistent input.
    #[doc(hidden)]
    pub fn import_persistence_state(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes)?;
        let sid = reader.array::<32>()?;
        let me = SigPublic::from_bytes(reader.array::<32>()?);
        let my_tag = reader.array::<8>()?;
        if my_tag != sender_tag(&me) {
            return Err(Error::MalformedState);
        }
        let retain = reader.count(MAX_RETAINED_VERSIONS)?;
        if retain == 0 {
            return Err(Error::MalformedState);
        }
        let version_count = reader.count(retain)?;
        let mut versions = BTreeMap::new();
        let mut previous_context: Option<ContextId> = None;
        for _ in 0..version_count {
            let context = reader.array::<16>()?;
            if previous_context.is_some_and(|previous| previous >= context) {
                return Err(Error::MalformedState);
            }
            previous_context = Some(context);
            versions.insert(context, read_version(&mut reader, context, my_tag)?);
        }
        let order = read_order(&mut reader, &versions, retain)?;
        let current = match reader.u8()? {
            0 => None,
            1 => Some(reader.array::<16>()?),
            _ => return Err(Error::MalformedState),
        };
        reader.finish()?;
        if current.is_some_and(|context| !versions.contains_key(&context))
            || (versions.is_empty() != current.is_none())
        {
            return Err(Error::MalformedState);
        }
        Ok(Self {
            sid,
            me,
            my_tag,
            versions,
            order,
            current,
            retain,
        })
    }

    /// Validates the cross-layer session, identity, key, and roster binding.
    #[doc(hidden)]
    pub fn validate_persistence_binding(
        &self,
        sid: [u8; 32],
        me: SigPublic,
        current: Option<([u8; 8], &Secret<KEY_LEN>, &BTreeSet<SigPublic>)>,
    ) -> Result<()> {
        if self.sid != sid || self.me != me || self.my_tag != sender_tag(&me) {
            return Err(Error::MalformedState);
        }
        if let Some((version, key, members)) = current {
            let context = context_id(version);
            if self.current != Some(context) {
                return Err(Error::MalformedState);
            }
            let stored = self.versions.get(&context).ok_or(Error::MalformedState)?;
            let roster: BTreeSet<SigPublic> = stored.roster.values().copied().collect();
            if stored.version != version || !stored.key.ct_eq(key) || &roster != members {
                return Err(Error::MalformedState);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Codec;
    use cfr_crypto::SigSecret;

    #[test]
    fn media_state_preserves_sender_counter() {
        let identity = SigSecret::from_seed(&[7; 32]);
        let mut protector = Protector::new([3; 32], identity.public(), 4);
        protector.install([9; 8], &Secret::from([4; KEY_LEN]), [identity.public()]);
        let first = protector.protect(Codec::Generic, b"frame", false).unwrap();
        assert_eq!(Protector::inspect(&first).unwrap().counter, 0);

        let bytes = protector.export_persistence_state().unwrap();
        let mut restored = Protector::import_persistence_state(&bytes).unwrap();
        assert_eq!(restored.export_persistence_state().unwrap(), bytes);
        let second = restored.protect(Codec::Generic, b"frame", false).unwrap();
        assert_eq!(Protector::inspect(&second).unwrap().counter, 1);
        assert_ne!(first, second);
    }

    #[test]
    fn media_state_rejects_trailing_bytes() {
        let identity = SigSecret::from_seed(&[7; 32]);
        let protector = Protector::new([3; 32], identity.public(), 4);
        let mut bytes = protector.export_persistence_state().unwrap();
        bytes.push(0);
        assert_eq!(
            Protector::import_persistence_state(&bytes).err(),
            Some(Error::MalformedState)
        );
    }
}
