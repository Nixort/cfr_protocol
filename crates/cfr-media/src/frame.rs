// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Protected media frame format and processing.
use crate::codec::{layout, Codec, Layout};
use crate::error::{Error, Result};
use crate::ratchet::{RecvRatchet, SendRatchet};
use crate::replay::Replay;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use cfr_crypto::{
    aead_open_detached, aead_open_detached_short, aead_seal_detached, aead_seal_detached_short,
    hash, Secret, SigPublic, KEY_LEN, TAG_LEN, TAG_LEN_SHORT,
};

/// Width of a current trailer.
pub const TRAILER_LEN: usize = 33;

/// An eight-byte sender routing identifier carried in every frame.
pub type SenderTag = [u8; 8];

/// A full media context identifier derived from the group-key version.
pub type ContextId = [u8; 16];

/// Derives the sender tag of an identity.
pub fn sender_tag(id: &SigPublic) -> SenderTag {
    let digest = hash(b"cfr/media/sender", &[id.as_bytes()]);
    digest[..8]
        .try_into()
        .expect("hash has at least eight bytes")
}

pub(crate) fn context_id(version: [u8; 8]) -> ContextId {
    let digest = hash(b"cfr/media/context", &[&version]);
    digest[..16]
        .try_into()
        .expect("hash has at least sixteen bytes")
}

fn codec_id(c: Codec) -> u8 {
    match c {
        Codec::H264 => 1,
        Codec::H265 => 2,
        Codec::Av1 => 3,
        Codec::Vp8 => 4,
        Codec::Vp9 => 5,
        Codec::Opus => 6,
        Codec::Generic => 0,
    }
}

fn codec_of(id: u8) -> Option<Codec> {
    Some(match id {
        0 => Codec::Generic,
        1 => Codec::H264,
        2 => Codec::H265,
        3 => Codec::Av1,
        4 => Codec::Vp8,
        5 => Codec::Vp9,
        6 => Codec::Opus,
        _ => return None,
    })
}

/// The parsed trailer of a protected frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Trailer {
    /// Who sent it.
    pub sender: SenderTag,
    /// Per-sender frame index.
    pub counter: u64,
    /// Full context identifier for the group key version.
    pub version: ContextId,
    /// The codec.
    pub codec: Codec,
    /// Whether this is a key frame.
    pub keyframe: bool,
}

impl Trailer {
    fn encode(&self) -> [u8; TRAILER_LEN] {
        let mut t = [0u8; TRAILER_LEN];
        t[0..8].copy_from_slice(&self.sender);
        t[8..16].copy_from_slice(&self.counter.to_be_bytes());
        t[16..32].copy_from_slice(&self.version);
        t[32] = 0x80 | (codec_id(self.codec) << 1) | u8::from(self.keyframe);
        t
    }

    /// Reads a trailer from the end of a protected frame.
    pub fn decode(buf: &[u8; TRAILER_LEN]) -> Result<Self> {
        if buf[32] & 0x80 == 0 {
            return Err(Error::Malformed);
        }
        let codec = codec_of((buf[32] & 0x7F) >> 1).ok_or(Error::Malformed)?;
        Ok(Self {
            sender: buf[0..8].try_into().expect("validated trailer width"),
            counter: u64::from_be_bytes(buf[8..16].try_into().expect("validated trailer width")),
            version: buf[16..32].try_into().expect("validated trailer width"),
            codec,
            keyframe: buf[32] & 1 == 1,
        })
    }
}

fn nonce_for(sid: &[u8; 32], t: &Trailer) -> [u8; 32] {
    cfr_crypto::nonce(&[
        sid,
        &t.sender,
        &t.version,
        &t.counter.to_be_bytes(),
        &[codec_id(t.codec)],
    ])
}

/// Builds the associated data: the trailer followed by every readable range.
fn associated(trailer: &[u8; TRAILER_LEN], frame: &[u8], l: &Layout) -> Vec<u8> {
    let mut ad = Vec::with_capacity(TRAILER_LEN + 16);
    ad.extend_from_slice(trailer);
    for r in &l.clear {
        ad.extend_from_slice(&frame[r.clone()]);
    }
    ad
}

/// Gathers the content ranges into one contiguous buffer.
fn gather(frame: &[u8], l: &Layout) -> Vec<u8> {
    let mut out = Vec::with_capacity(l.secret_len());
    for r in &l.secret {
        out.extend_from_slice(&frame[r.clone()]);
    }
    out
}

/// Writes contiguous content bytes back into their original positions.
fn scatter(frame: &mut [u8], l: &Layout, data: &[u8]) {
    let mut pos = 0usize;
    for r in &l.secret {
        let n = r.len();
        frame[r.clone()].copy_from_slice(&data[pos..pos + n]);
        pos += n;
    }
}

pub(crate) struct VersionKeys {
    pub(crate) version: [u8; 8],
    pub(crate) key: Secret<KEY_LEN>,
    pub(crate) roster: BTreeMap<SenderTag, SigPublic>,
    pub(crate) send: SendRatchet,
    pub(crate) recv: BTreeMap<SenderTag, (RecvRatchet, Replay)>,
    /// Frames sent under this context.
    ///
    /// The index is context-scoped to prevent nonce reuse after reselection.
    pub(crate) counter: u64,
}

/// Protects and opens media frames for one participant.
///
/// Recent versions tolerate in-flight rekeys; eviction erases older key material.
pub struct Protector {
    pub(crate) sid: [u8; 32],
    pub(crate) me: SigPublic,
    pub(crate) my_tag: SenderTag,
    pub(crate) versions: BTreeMap<ContextId, VersionKeys>,
    pub(crate) order: VecDeque<ContextId>,
    pub(crate) current: Option<ContextId>,
    pub(crate) retain: usize,
}

impl Protector {
    /// Creates a protector for `me` in conference `sid`, retaining `retain`
    /// key versions.
    pub fn new(sid: [u8; 32], me: SigPublic, retain: usize) -> Self {
        Self {
            sid,
            me,
            my_tag: sender_tag(&me),
            versions: BTreeMap::new(),
            order: VecDeque::new(),
            current: None,
            retain: retain.max(1),
        }
    }

    /// Installs a group key version and makes it current.
    ///
    /// `roster` maps sender tags to version members. Reinstalling an existing
    /// version preserves its ratchets and counter.
    pub fn install(
        &mut self,
        version: [u8; 8],
        key: &Secret<KEY_LEN>,
        roster: impl IntoIterator<Item = SigPublic>,
    ) {
        let context = context_id(version);
        if self.versions.contains_key(&context) {
            self.current = Some(context);
            return;
        }
        let roster: BTreeMap<SenderTag, SigPublic> =
            roster.into_iter().map(|m| (sender_tag(&m), m)).collect();
        let vk = VersionKeys {
            version,
            key: key.clone(),
            send: SendRatchet::new(key, &self.me),
            roster,
            recv: BTreeMap::new(),
            counter: 0,
        };
        self.versions.insert(context, vk);
        self.order.push_back(context);
        self.current = Some(context);
        while self.order.len() > self.retain {
            let old = self
                .order
                .pop_front()
                .expect("version queue is non-empty while over retention limit");
            if let Some(mut v) = self.versions.remove(&old) {
                v.key.wipe();
            }
        }
    }

    /// The version currently used for sending.
    pub fn current_version(&self) -> Option<[u8; 8]> {
        self.versions.get(&self.current?).map(|v| v.version)
    }

    /// How many versions are retained.
    pub fn retained(&self) -> usize {
        self.versions.len()
    }

    /// Protects one frame.
    pub fn protect(&mut self, codec: Codec, frame: &[u8], keyframe: bool) -> Result<Vec<u8>> {
        let context = self.current.ok_or(Error::NoKey)?;
        let counter = {
            let vk = self.versions.get_mut(&context).ok_or(Error::NoKey)?;
            let c = vk.counter;
            vk.counter = vk.counter.checked_add(1).ok_or(Error::CounterExhausted)?;
            c
        };

        let l = layout(codec, frame, keyframe);
        debug_assert!(l.tiles(frame.len()));
        let trailer = Trailer {
            sender: self.my_tag,
            counter,
            version: context,
            codec,
            keyframe,
        };
        let raw = trailer.encode();
        let nonce = nonce_for(&self.sid, &trailer);
        let ad = associated(&raw, frame, &l);

        let vk = self.versions.get_mut(&context).ok_or(Error::NoKey)?;
        let fk = vk.send.key(counter).ok_or(Error::NoKey)?;

        let mut protected = gather(frame, &l);
        let mut out = frame.to_vec();
        if codec.is_audio() {
            let tag = aead_seal_detached_short(fk.as_bytes(), &nonce, &mut protected, &ad);
            scatter(&mut out, &l, &protected);
            out.extend_from_slice(&tag);
        } else {
            let tag = aead_seal_detached(fk.as_bytes(), &nonce, &mut protected, &ad);
            scatter(&mut out, &l, &protected);
            out.extend_from_slice(&tag);
        }
        out.extend_from_slice(&raw);
        Ok(out)
    }

    /// Opens one protected frame, returning the sender and the original bytes.
    pub fn unprotect(&mut self, packet: &[u8]) -> Result<(SigPublic, Vec<u8>)> {
        if packet.len() < TRAILER_LEN {
            return Err(Error::Malformed);
        }
        let (rest, raw) = packet.split_at(packet.len() - TRAILER_LEN);
        let raw: [u8; TRAILER_LEN] = raw.try_into().expect("split at TRAILER_LEN");
        let trailer = Trailer::decode(&raw)?;

        let tag_len = if trailer.codec.is_audio() {
            TAG_LEN_SHORT
        } else {
            TAG_LEN
        };
        if rest.len() < tag_len {
            return Err(Error::Malformed);
        }
        let (body, tag) = rest.split_at(rest.len() - tag_len);

        let vk = self
            .versions
            .get_mut(&trailer.version)
            .ok_or(Error::UnknownVersion)?;
        let sender = *vk.roster.get(&trailer.sender).ok_or(Error::UnknownSender)?;
        if sender == self.me {
            return Err(Error::OwnFrame);
        }

        let entry = vk
            .recv
            .entry(trailer.sender)
            .or_insert_with(|| (RecvRatchet::new(&vk.key, &sender), Replay::new()));

        // Commit replay and ratchet state only after AEAD verification.
        let mut next_ratchet = entry.0.clone();
        let mut next_replay = entry.1.clone();
        if !next_replay.accept(trailer.counter) {
            return Err(Error::Replay);
        }
        let fk = next_ratchet.key(trailer.counter).ok_or(Error::Stale)?;

        let l = layout(trailer.codec, body, trailer.keyframe);
        debug_assert!(l.tiles(body.len()));
        let nonce = nonce_for(&self.sid, &trailer);
        let ad = associated(&raw, body, &l);

        let mut content = gather(body, &l);
        if trailer.codec.is_audio() {
            let tag: [u8; TAG_LEN_SHORT] = tag.try_into().map_err(|_| Error::Malformed)?;
            aead_open_detached_short(fk.as_bytes(), &nonce, &mut content, &tag, &ad)
                .map_err(|_| Error::BadTag)?;
        } else {
            let tag: [u8; TAG_LEN] = tag.try_into().map_err(|_| Error::Malformed)?;
            aead_open_detached(fk.as_bytes(), &nonce, &mut content, &tag, &ad)
                .map_err(|_| Error::BadTag)?;
        }
        entry.0 = next_ratchet;
        entry.1 = next_replay;
        let mut out = body.to_vec();
        scatter(&mut out, &l, &content);
        Ok((sender, out))
    }

    /// Reads the trailer of a protected frame without holding any key.
    ///
    /// This is what a selective forwarding unit calls. It reveals the sender
    /// tag, frame index, context ID, codec, and keyframe flag but no content.
    pub fn inspect(packet: &[u8]) -> Result<Trailer> {
        if packet.len() < TRAILER_LEN {
            return Err(Error::Malformed);
        }
        let raw: [u8; TRAILER_LEN] = packet[packet.len() - TRAILER_LEN..]
            .try_into()
            .expect("split at TRAILER_LEN");
        Trailer::decode(&raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfr_crypto::SigSecret;

    fn pair() -> (Protector, Protector, SigPublic, SigPublic) {
        let a = SigSecret::from_seed(&[1u8; 32]).public();
        let b = SigSecret::from_seed(&[2u8; 32]).public();
        let sid = [7u8; 32];
        let key = Secret::from([42u8; 32]);
        let mut pa = Protector::new(sid, a, 4);
        let mut pb = Protector::new(sid, b, 4);
        pa.install([1u8; 8], &key, [a, b]);
        pb.install([1u8; 8], &key, [a, b]);
        (pa, pb, a, b)
    }

    #[test]
    fn trailer_without_format_marker_is_rejected() {
        let trailer = Trailer {
            sender: [1u8; 8],
            counter: 7,
            version: [2u8; 16],
            codec: Codec::Generic,
            keyframe: false,
        };
        let mut raw = trailer.encode();
        raw[32] &= 0x7F;
        assert!(matches!(Trailer::decode(&raw), Err(Error::Malformed)));
    }

    #[test]
    fn roundtrip_for_every_codec() {
        for codec in [
            Codec::H264,
            Codec::H265,
            Codec::Av1,
            Codec::Vp8,
            Codec::Vp9,
            Codec::Opus,
            Codec::Generic,
        ] {
            let (mut pa, mut pb, a, _) = pair();
            let frame: Vec<u8> = (0u8..90).collect();
            let sealed = pa.protect(codec, &frame, true).unwrap();
            let (who, back) = pb.unprotect(&sealed).unwrap();
            assert_eq!(who, a, "{codec:?}");
            assert_eq!(back, frame, "{codec:?}");
        }
    }

    #[test]
    fn structure_survives_and_content_does_not() {
        let (mut pa, _, _, _) = pair();
        let frame = [0u8, 0, 0, 1, 0x65, 0xDE, 0xAD, 0xBE, 0xEF];
        let sealed = pa.protect(Codec::H264, &frame, true).unwrap();
        // The start code and NAL header are byte-identical.
        assert_eq!(&sealed[..5], &frame[..5]);
        // The payload is not.
        assert_ne!(&sealed[5..9], &frame[5..9]);
        assert_eq!(sealed.len(), frame.len() + TAG_LEN + TRAILER_LEN);
    }

    #[test]
    fn a_forwarder_can_inspect_without_a_key() {
        let (mut pa, _, a, _) = pair();
        let sealed = pa.protect(Codec::Vp8, &[0x10u8; 40], true).unwrap();
        let t = Protector::inspect(&sealed).unwrap();
        assert_eq!(t.sender, sender_tag(&a));
        assert_eq!(t.codec, Codec::Vp8);
        assert!(t.keyframe);
        assert_eq!(t.counter, 0);
    }

    #[test]
    fn audio_uses_the_short_tag() {
        let (mut pa, mut pb, _, _) = pair();
        let frame = [0x78u8, 1, 2, 3, 4, 5];
        let sealed = pa.protect(Codec::Opus, &frame, false).unwrap();
        assert_eq!(sealed.len(), frame.len() + TAG_LEN_SHORT + TRAILER_LEN);
        assert_eq!(pb.unprotect(&sealed).unwrap().1, frame);
    }

    #[test]
    fn tampering_anywhere_is_detected() {
        let frame: Vec<u8> = (0u8..40).collect();
        for i in 0..(frame.len() + TAG_LEN + TRAILER_LEN) {
            let (mut pa, mut pb, _, _) = pair();
            let mut sealed = pa.protect(Codec::H264, &frame, false).unwrap();
            sealed[i] ^= 0x01;
            let r = pb.unprotect(&sealed);
            assert!(r.is_err(), "mutation at byte {i} went undetected");
        }
    }

    #[test]
    fn cleartext_header_is_authenticated() {
        // The whole point of putting structure in the associated data: a
        // forwarder may read it but must not be able to rewrite it.
        let (mut pa, mut pb, _, _) = pair();
        let frame = [0u8, 0, 0, 1, 0x65, 1, 2, 3];
        let mut sealed = pa.protect(Codec::H264, &frame, false).unwrap();
        sealed[4] = 0x41; // rewrite the NAL header
        assert!(matches!(pb.unprotect(&sealed), Err(Error::BadTag)));
    }

    #[test]
    fn an_unauthenticated_frame_does_not_consume_its_counter() {
        let (mut sender, mut receiver, _, _) = pair();
        let frame = b"genuine";
        let genuine = sender.protect(Codec::Generic, frame, false).unwrap();
        let mut forged = genuine.clone();
        forged[0] ^= 0x01;

        assert!(matches!(receiver.unprotect(&forged), Err(Error::BadTag)));
        assert_eq!(receiver.unprotect(&genuine).unwrap().1, frame);
    }

    #[test]
    fn replayed_frames_are_refused() {
        let (mut pa, mut pb, _, _) = pair();
        let sealed = pa.protect(Codec::Generic, b"hello", false).unwrap();
        assert!(pb.unprotect(&sealed).is_ok());
        assert!(matches!(pb.unprotect(&sealed), Err(Error::Replay)));
    }

    #[test]
    fn a_frame_from_an_unknown_version_is_refused() {
        let (mut pa, mut pb, _, _) = pair();
        let sealed = pa.protect(Codec::Generic, b"x", false).unwrap();
        pb.versions.clear();
        assert!(matches!(pb.unprotect(&sealed), Err(Error::UnknownVersion)));
    }

    #[test]
    fn frames_still_open_across_a_rekey() {
        let (mut pa, mut pb, _, b) = pair();
        let old = pa.protect(Codec::Generic, b"before", false).unwrap();
        let k2 = Secret::from([99u8; 32]);
        let roster = [pa.me, b];
        pa.install([2u8; 8], &k2, roster);
        pb.install([2u8; 8], &k2, roster);
        let new = pa.protect(Codec::Generic, b"after", false).unwrap();
        assert_eq!(pb.unprotect(&new).unwrap().1, b"after");
        assert_eq!(
            pb.unprotect(&old).unwrap().1,
            b"before",
            "in-flight frames from the previous version must still open"
        );
    }

    #[test]
    fn a_retired_version_can_no_longer_be_opened() {
        let (mut pa, mut pb, _, b) = pair();
        let old = pa.protect(Codec::Generic, b"ancient", false).unwrap();
        for i in 2u8..8 {
            let k = Secret::from([i; 32]);
            let roster = [pa.me, b];
            pa.install([i; 8], &k, roster);
            pb.install([i; 8], &k, roster);
        }
        assert_eq!(pb.retained(), 4);
        assert!(matches!(pb.unprotect(&old), Err(Error::UnknownVersion)));
    }

    #[test]
    fn reinstalling_a_version_does_not_reuse_a_nonce() {
        // The counter must survive a re-selection of the same version, or two
        // frames would be encrypted under the same key and nonce.
        let (mut pa, mut pb, _, b) = pair();
        let key = Secret::from([42u8; 32]);
        let first = pa.protect(Codec::Generic, b"one", false).unwrap();
        pa.install([1u8; 8], &key, [pa.me, b]);
        let second = pa.protect(Codec::Generic, b"two", false).unwrap();
        assert_eq!(Protector::inspect(&first).unwrap().counter, 0);
        assert_eq!(
            Protector::inspect(&second).unwrap().counter,
            1,
            "re-installing must not restart the counter"
        );
        assert!(pb.unprotect(&first).is_ok());
        assert!(pb.unprotect(&second).is_ok());
    }

    #[test]
    fn returning_to_an_earlier_version_keeps_its_ratchet() {
        let (mut pa, mut pb, _, b) = pair();
        let k1 = Secret::from([42u8; 32]);
        let k2 = Secret::from([43u8; 32]);
        let roster = [pa.me, b];
        let a1 = pa.protect(Codec::Generic, b"other-a", false).unwrap();
        pa.install([2u8; 8], &k2, roster);
        pb.install([2u8; 8], &k2, roster);
        let _ = pa.protect(Codec::Generic, b"current", false).unwrap();
        pa.install([1u8; 8], &k1, roster);
        let a2 = pa.protect(Codec::Generic, b"other-b", false).unwrap();
        assert_ne!(
            Protector::inspect(&a1).unwrap().counter,
            Protector::inspect(&a2).unwrap().counter
        );
        assert!(pb.unprotect(&a1).is_ok());
        assert!(pb.unprotect(&a2).is_ok());
    }

    #[test]
    fn a_participant_rejects_its_own_frames() {
        let (mut pa, _, _, _) = pair();
        let sealed = pa.protect(Codec::Generic, b"mine", false).unwrap();
        assert!(matches!(pa.unprotect(&sealed), Err(Error::OwnFrame)));
    }

    #[test]
    fn truncated_packets_are_refused() {
        let (mut pa, mut pb, _, _) = pair();
        let sealed = pa.protect(Codec::H264, b"0123456789", false).unwrap();
        for cut in 0..sealed.len() {
            assert!(pb.unprotect(&sealed[..cut]).is_err(), "cut {cut}");
        }
    }

    #[test]
    fn empty_frames_roundtrip() {
        let (mut pa, mut pb, _, _) = pair();
        let sealed = pa.protect(Codec::Generic, b"", false).unwrap();
        assert_eq!(pb.unprotect(&sealed).unwrap().1, b"");
    }
}
