// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! One participant's whole view of a call.

use alloc::vec::Vec;
use cfr_core::{
    Beacon, CheckpointCertificate, Destination, Event, KeyPackage, Outbound, Participant,
    PendingJoin, Policy, ProtocolProfile, ResumptionRecord, SessionId,
};
use cfr_crypto::SigPublic;
use cfr_media::{Codec, Protector, Trailer};

/// How many group key versions the media layer keeps openable.
///
/// Frames in flight when the group rekeys must still open, so more than one is
/// required. Every retained version is also a version a memory snapshot could
/// decrypt, so the number is small and fixed rather than generous.
pub const MEDIA_OVERLAP: usize = 4;

/// Where an outbound message goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recipient {
    /// Every current participant.
    Everyone,
    /// One named participant.
    Peer(SigPublic),
}

impl From<Destination> for Recipient {
    fn from(d: Destination) -> Self {
        match d {
            Destination::Everyone => Self::Everyone,
            Destination::Peer(p) => Self::Peer(p),
        }
    }
}

/// A message the application must deliver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Who should receive it.
    pub to: Recipient,
    /// The bytes to deliver, unmodified.
    pub payload: Vec<u8>,
}

impl From<Outbound> for Message {
    fn from(o: Outbound) -> Self {
        Self {
            to: o.to.into(),
            payload: o.payload,
        }
    }
}

/// Anything that can go wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum Error {
    /// Key management failed.
    #[cfg_attr(feature = "std", error("key management: {0}"))]
    Key(cfr_core::Error),
    /// Media protection failed.
    #[cfg_attr(feature = "std", error("media: {0}"))]
    Media(cfr_media::Error),
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<cfr_core::Error> for Error {
    fn from(e: cfr_core::Error) -> Self {
        Self::Key(e)
    }
}

impl From<cfr_media::Error> for Error {
    fn from(e: cfr_media::Error) -> Self {
        Self::Media(e)
    }
}

/// Convenience alias.
pub type Result<T> = core::result::Result<T, Error>;

/// A participant that has generated identity material but not yet joined.
pub struct Joining(PendingJoin);

impl Joining {
    /// Generates identity and prekey material.
    pub fn new(policy: Policy) -> Result<Self> {
        Ok(Self(PendingJoin::new(policy)?))
    }

    /// The package to hand to an inviter out of band.
    ///
    /// It is self-signed, so an inviter cannot substitute a prekey it controls
    /// and read the welcome. Deliver it over a channel that authenticates the
    /// identity; the library cannot tell one stranger from another.
    pub fn key_package(&self) -> KeyPackage {
        self.0.key_package()
    }

    /// The identity this participant will use.
    pub fn identity(&self) -> SigPublic {
        self.0.identity()
    }

    /// Consumes a welcome and joins.
    pub fn accept(self, welcome: &[u8]) -> Result<(Conference, Vec<Message>)> {
        let (p, out) = self.0.accept(welcome)?;
        Ok(Conference::wrap(p, out))
    }
}

/// One participant's seat in a conference.
pub struct Conference {
    core: Participant,
    media: Protector,
}

impl Conference {
    fn wrap(core: Participant, out: Vec<Outbound>) -> (Self, Vec<Message>) {
        let media = Protector::new(core.session_id(), core.identity(), MEDIA_OVERLAP);
        let mut c = Self { core, media };
        c.refresh_media();
        (c, out.into_iter().map(Into::into).collect())
    }

    /// Starts a conference.
    pub fn create(policy: Policy) -> Result<(Self, Vec<Message>)> {
        let (p, out) = Participant::create(policy)?;
        Ok(Self::wrap(p, out))
    }

    /// Installs the current group key into the media layer.
    ///
    /// Called automatically whenever the key changes. Doing it eagerly, rather
    /// than lazily on the first frame, keeps the previous version available for
    /// frames already in flight.
    fn refresh_media(&mut self) {
        if let Some(k) = self.core.group_key() {
            let v = self.core.version();
            if self.media.current_version() != Some(v) {
                self.media.install(v, &k, self.core.members());
            }
        }
    }

    // ---------------------------------------------------------------- state

    /// This participant's identity.
    pub fn identity(&self) -> SigPublic {
        self.core.identity()
    }

    /// The conference identifier.
    pub fn session_id(&self) -> SessionId {
        self.core.session_id()
    }

    /// Who is present.
    pub fn members(&self) -> alloc::collections::BTreeSet<SigPublic> {
        self.core.members()
    }

    /// The current key version label.
    pub fn version(&self) -> [u8; 8] {
        self.core.version()
    }

    /// Whether the current key can be derived locally.
    pub fn ready(&self) -> bool {
        self.core.can_derive()
    }

    /// Whether repair is needed to derive the current key.
    pub fn needs_repair(&self) -> bool {
        self.core.needs_repair()
    }

    /// Number of history operations retained.
    pub fn history_len(&self) -> usize {
        self.core.history_len()
    }

    /// Approximate retained state in bytes.
    pub fn state_bytes(&self) -> usize {
        self.core.state_bytes()
    }

    /// Returns true when a signed reinitialization should be prepared.
    pub fn reinitialization_recommended(&self) -> bool {
        self.core.reinitialization_recommended()
    }

    /// Prepares a current resumption record for active members to sign.
    pub fn prepare_checkpoint(
        &self,
        next_session: SessionId,
        checkpoint_epoch: u64,
        profile: ProtocolProfile,
    ) -> Result<ResumptionRecord> {
        Ok(self
            .core
            .prepare_checkpoint(next_session, checkpoint_epoch, profile)?)
    }

    /// Signs a locally verified checkpoint record with this participant identity.
    pub fn approve_checkpoint(
        &self,
        record: &ResumptionRecord,
    ) -> Result<cfr_core::CheckpointSignature> {
        Ok(self.core.approve_checkpoint(record)?)
    }

    /// Validates and broadcasts a unanimously signed checkpoint certificate.
    ///
    /// Receiving this message yields a checkpoint offer; it never mutates the
    /// active conference or deletes history automatically.
    pub fn offer_checkpoint(&self, certificate: &CheckpointCertificate) -> Result<Message> {
        Ok(self.core.offer_checkpoint(certificate)?.into())
    }

    /// The key confirmation beacon to attach to outgoing media.
    pub fn beacon(&self) -> [u8; cfr_core::BEACON_LEN] {
        self.core.beacon()
    }

    /// Checks a peer's beacon.
    pub fn check_beacon(&self, peer: &SigPublic, beacon: &[u8; cfr_core::BEACON_LEN]) -> Beacon {
        self.core.check_beacon(peer, beacon)
    }

    // ------------------------------------------------------------ lifecycle

    /// Admits a newcomer.
    pub fn invite(&mut self, kp: &KeyPackage) -> Result<Vec<Message>> {
        let out = self.core.invite(kp)?;
        self.refresh_media();
        Ok(out.into_iter().map(Into::into).collect())
    }

    /// Evicts a participant and rekeys without it.
    pub fn evict(&mut self, who: &SigPublic) -> Result<Vec<Message>> {
        let out = self.core.remove(who)?;
        self.refresh_media();
        Ok(out.into_iter().map(Into::into).collect())
    }

    /// Leaves the conference.
    pub fn leave(&mut self) -> Result<Message> {
        Ok(self.core.leave()?.into())
    }

    /// Contributes fresh entropy, moving the key forward.
    pub fn rekey(&mut self) -> Result<Vec<Message>> {
        let out = self.core.contribute()?;
        self.refresh_media();
        Ok(out.into_iter().map(Into::into).collect())
    }

    /// Rotates this participant's prekey. Do this after any suspicion of
    /// compromise; combined with [`Conference::rekey`] it restores secrecy.
    pub fn heal(&mut self) -> Result<Vec<Message>> {
        let rotate = self.core.rotate_prekeys()?;
        let mut out = alloc::vec![Message::from(rotate)];
        out.extend(self.rekey()?);
        Ok(out)
    }

    /// Advances deadline clocks. Call about once per rotation interval.
    pub fn tick(&mut self) {
        self.core.tick();
    }

    // -------------------------------------------------------------- traffic

    /// Processes one received control message.
    pub fn handle(&mut self, wire: &[u8]) -> Result<(Vec<Event>, Vec<Message>)> {
        let (events, out) = self.core.handle(wire)?;
        self.refresh_media();
        Ok((events, out.into_iter().map(Into::into).collect()))
    }

    /// Asks the conference for anything this participant is missing.
    pub fn resync(&mut self) -> Vec<Message> {
        let mut out = alloc::vec![Message::from(self.core.sync_request())];
        if let Some(more) = self.core.repair_request() {
            out.extend(more.into_iter().map(Message::from));
        }
        out
    }

    /// Protects one media frame.
    pub fn protect(&mut self, codec: Codec, frame: &[u8], keyframe: bool) -> Result<Vec<u8>> {
        self.refresh_media();
        Ok(self.media.protect(codec, frame, keyframe)?)
    }

    /// Opens one protected media frame.
    ///
    /// The key is refreshed first. A repair can make the current version
    /// derivable without any further control message arriving, and a receiver
    /// that only refreshed on inbound control traffic would sit there unable
    /// to open frames it now has the key for.
    pub fn open(&mut self, packet: &[u8]) -> Result<(SigPublic, Vec<u8>)> {
        self.refresh_media();
        Ok(self.media.unprotect(packet)?)
    }

    /// Reads a frame's routing metadata without any key. A forwarder calls
    /// this; it never needs to be a participant.
    pub fn inspect(packet: &[u8]) -> Result<Trailer> {
        Ok(Protector::inspect(packet)?)
    }
}
