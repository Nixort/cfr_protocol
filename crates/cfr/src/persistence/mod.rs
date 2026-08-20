// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Crash-safe, versioned persistence for [`crate::Conference`].
//!
//! Every mutating operation uses a copy-on-write transaction: the candidate
//! state is validated, appended to the WAL, and synchronized before it becomes
//! the live in-memory state. Control messages leave this boundary only through
//! the durable outbox.

mod state;
mod store;

use crate::{
    Beacon, CheckpointCertificate, CheckpointSignature, Codec, Conference, Event, Joining,
    KeyPackage, Policy, ProtocolProfile, Recipient, ResumptionRecord, SessionId, SigPublic,
    Trailer,
};
use state::LogicalState;
use std::collections::BTreeSet;
use std::path::Path;
use store::Store;

/// Current logical schema version of a persisted conference state.
///
/// This is independent of both the CFR wire protocol and the store envelope.
pub const CURRENT_PERSISTENCE_SCHEMA_VERSION: u32 = 1;

pub(crate) const HARD_MAX_STATE_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const HARD_MAX_WAL_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_WINDOW_ENTRIES: usize = 65_536;

/// Identifies which internal version tag was unsupported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionKind {
    /// The logical conference-state schema.
    PersistenceSchema,
    /// The snapshot or WAL envelope.
    StoreEnvelope,
}

/// A transport-supplied stable identifier for one inbound control message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InboundId([u8; 32]);

impl InboundId {
    /// Creates an identifier from transport-owned bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the transport-owned bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for InboundId {
    fn from(value: [u8; 32]) -> Self {
        Self::from_bytes(value)
    }
}

/// A monotonically increasing durable outbox identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutboundId(u64);

impl OutboundId {
    /// Returns the numeric identifier.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A deterministic transport retry key for one exact delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeliveryKey([u8; 32]);

impl DeliveryKey {
    /// Returns the key bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// One unacknowledged control message from the durable outbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingDelivery {
    /// Monotonic outbox identifier.
    pub id: OutboundId,
    /// Deterministic retry key bound to the ID, recipient, and payload.
    pub delivery_key: DeliveryKey,
    /// Intended protocol recipient.
    pub recipient: Recipient,
    /// Exact CFR control-message bytes.
    pub payload: Vec<u8>,
}

/// Result of an inbound durable transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundResult {
    /// True when the same transport ID and payload were committed previously.
    pub duplicate: bool,
    /// New protocol events; always empty for a duplicate.
    pub events: Vec<Event>,
    /// IDs added to the durable outbox by this transaction.
    pub deliveries: Vec<OutboundId>,
}

/// Resource and compaction settings persisted with the conference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersistenceOptions {
    /// Number of inbound IDs retained for durable idempotency.
    pub inbound_window: usize,
    /// Maximum number of unacknowledged control deliveries.
    pub max_outbox_entries: usize,
    /// Maximum encoded logical-state payload size.
    pub max_state_bytes: usize,
    /// Maximum payload size of one full-state WAL record.
    pub max_record_bytes: usize,
    /// Hard WAL file size limit.
    pub max_wal_bytes: u64,
    /// WAL size at which the current state is checkpointed before appending.
    pub checkpoint_threshold: u64,
}

impl Default for PersistenceOptions {
    fn default() -> Self {
        Self {
            inbound_window: 4_096,
            max_outbox_entries: 1_024,
            max_state_bytes: HARD_MAX_STATE_BYTES,
            max_record_bytes: HARD_MAX_STATE_BYTES,
            max_wal_bytes: HARD_MAX_WAL_BYTES,
            checkpoint_threshold: 32 * 1024 * 1024,
        }
    }
}

impl PersistenceOptions {
    pub(crate) fn validate(self) -> Result<Self> {
        if self.inbound_window == 0 || self.inbound_window > MAX_WINDOW_ENTRIES {
            return Err(Error::InvalidOptions("inbound window is out of range"));
        }
        if self.max_outbox_entries == 0 || self.max_outbox_entries > MAX_WINDOW_ENTRIES {
            return Err(Error::InvalidOptions("outbox limit is out of range"));
        }
        if self.max_state_bytes == 0 || self.max_state_bytes > HARD_MAX_STATE_BYTES {
            return Err(Error::InvalidOptions("state limit is out of range"));
        }
        if self.max_record_bytes == 0 || self.max_record_bytes > HARD_MAX_STATE_BYTES {
            return Err(Error::InvalidOptions("record limit is out of range"));
        }
        if self.max_wal_bytes == 0 || self.max_wal_bytes > HARD_MAX_WAL_BYTES {
            return Err(Error::InvalidOptions("WAL limit is out of range"));
        }
        if self.checkpoint_threshold == 0 || self.checkpoint_threshold > self.max_wal_bytes {
            return Err(Error::InvalidOptions(
                "checkpoint threshold exceeds WAL limit",
            ));
        }
        Ok(self)
    }
}

/// Errors from the versioned persistence boundary.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The requested state directory does not exist.
    #[error("persistent conference not found")]
    NotFound,
    /// Creation refused to reuse an existing path.
    #[error("persistent conference already exists")]
    AlreadyExists,
    /// Another process or handle owns the state directory lock.
    #[error("persistent conference is locked")]
    Locked,
    /// A complete persisted object was malformed or failed validation.
    #[error("persisted conference is corrupt: {0}")]
    Corrupt(&'static str),
    /// A persisted internal schema or envelope version is unknown.
    #[error("unsupported {kind:?} version {found}")]
    UnsupportedVersion {
        /// Version namespace that was rejected.
        kind: VersionKind,
        /// Unknown numeric version.
        found: u32,
    },
    /// An inbound ID was reused for different payload bytes.
    #[error("inbound idempotency conflict for {id:?}")]
    IdempotencyConflict {
        /// Conflicting transport identifier.
        id: InboundId,
    },
    /// A configured durable resource bound would be exceeded.
    #[error("persistence resource limit exceeded: {0}")]
    LimitExceeded(&'static str),
    /// Persistence options were internally inconsistent or out of range.
    #[error("invalid persistence options: {0}")]
    InvalidOptions(&'static str),
    /// A filesystem operation failed.
    #[error("persistence I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// The requested conference operation failed before commit.
    #[error("conference operation failed: {0}")]
    Protocol(#[from] crate::Error),
}

/// Convenience alias for persistence operations.
pub type Result<T> = std::result::Result<T, Error>;

/// A conference whose complete mutable state is committed before it is exposed.
pub struct PersistentConference {
    state: LogicalState,
    store: Store,
}

impl PersistentConference {
    /// Creates a new founder conference with default persistence limits.
    pub fn create(path: impl AsRef<Path>, policy: Policy) -> Result<Self> {
        Self::create_with_options(path, policy, PersistenceOptions::default())
    }

    /// Creates a new founder conference with explicit persisted limits.
    pub fn create_with_options(
        path: impl AsRef<Path>,
        policy: Policy,
        options: PersistenceOptions,
    ) -> Result<Self> {
        let options = options.validate()?;
        let (conference, messages) = Conference::create(policy)?;
        Self::create_from_conference(path.as_ref(), conference, messages, options)
    }

    /// Accepts a welcome into a newly created persistent state directory.
    pub fn join(path: impl AsRef<Path>, joining: Joining, welcome: &[u8]) -> Result<Self> {
        Self::join_with_options(path, joining, welcome, PersistenceOptions::default())
    }

    /// Accepts a welcome with explicit persisted limits.
    pub fn join_with_options(
        path: impl AsRef<Path>,
        joining: Joining,
        welcome: &[u8],
        options: PersistenceOptions,
    ) -> Result<Self> {
        let options = options.validate()?;
        let (conference, messages) = joining.accept(welcome)?;
        Self::create_from_conference(path.as_ref(), conference, messages, options)
    }

    fn create_from_conference(
        path: &Path,
        conference: Conference,
        messages: Vec<crate::Message>,
        options: PersistenceOptions,
    ) -> Result<Self> {
        let state = LogicalState::new(conference, messages, options)?;
        let payload = state.encode()?;
        let store = Store::create(path, state.sequence, &payload)?;
        Ok(Self { state, store })
    }

    /// Opens an existing state directory; absence never creates a new identity.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let (store, recovery) = Store::open(path.as_ref())?;
        let state = LogicalState::recover(recovery)?;
        store.validate_runtime_limits(&state.options)?;
        Ok(Self { state, store })
    }

    /// This participant's stable identity.
    pub fn identity(&self) -> SigPublic {
        self.state.conference.identity()
    }

    /// The stable conference session identifier.
    pub fn session_id(&self) -> SessionId {
        self.state.conference.session_id()
    }

    /// Current conference members.
    pub fn members(&self) -> BTreeSet<SigPublic> {
        self.state.conference.members()
    }

    /// Current key-version label.
    pub fn version(&self) -> [u8; 8] {
        self.state.conference.version()
    }

    /// Monotonic committed persistence transaction sequence.
    pub fn sequence(&self) -> u64 {
        self.state.sequence
    }

    /// Persisted resource and compaction settings.
    pub fn options(&self) -> PersistenceOptions {
        self.state.options
    }

    /// Whether the current group key is locally derivable.
    pub fn ready(&self) -> bool {
        self.state.conference.ready()
    }

    /// Whether current node-key repair is required.
    pub fn needs_repair(&self) -> bool {
        self.state.conference.needs_repair()
    }

    /// Number of retained signed history operations.
    pub fn history_len(&self) -> usize {
        self.state.conference.history_len()
    }

    /// Approximate retained protocol-state size.
    pub fn state_bytes(&self) -> usize {
        self.state.conference.state_bytes()
    }

    /// Whether the active session should prepare signed reinitialization.
    pub fn reinitialization_recommended(&self) -> bool {
        self.state.conference.reinitialization_recommended()
    }

    /// Prepares a non-mutating signed-session transition record.
    pub fn prepare_checkpoint(
        &self,
        next_session: SessionId,
        checkpoint_epoch: u64,
        profile: ProtocolProfile,
    ) -> Result<ResumptionRecord> {
        Ok(self
            .state
            .conference
            .prepare_checkpoint(next_session, checkpoint_epoch, profile)?)
    }

    /// Signs a locally verified transition record without mutating conference state.
    pub fn approve_checkpoint(&self, record: &ResumptionRecord) -> Result<CheckpointSignature> {
        Ok(self.state.conference.approve_checkpoint(record)?)
    }

    /// Durably queues a validated checkpoint offer.
    pub fn offer_checkpoint(
        &mut self,
        certificate: &CheckpointCertificate,
    ) -> Result<Vec<OutboundId>> {
        self.mutate_conference(|conference| {
            let message = conference.offer_checkpoint(certificate)?;
            Ok(((), vec![message]))
        })
        .map(|((), deliveries)| deliveries)
    }

    /// Returns a key-confirmation beacon without mutating state.
    pub fn beacon(&self) -> [u8; cfr_core::BEACON_LEN] {
        self.state.conference.beacon()
    }

    /// Checks a peer key-confirmation beacon without mutating state.
    pub fn check_beacon(&self, peer: &SigPublic, beacon: &[u8; cfr_core::BEACON_LEN]) -> Beacon {
        self.state.conference.check_beacon(peer, beacon)
    }

    /// Admits a newcomer and durably queues every resulting control message.
    pub fn invite(&mut self, key_package: &KeyPackage) -> Result<Vec<OutboundId>> {
        self.mutate_conference(|conference| {
            let messages = conference.invite(key_package)?;
            Ok(((), messages))
        })
        .map(|((), deliveries)| deliveries)
    }

    /// Evicts a participant and durably queues removal and rekey messages.
    pub fn evict(&mut self, who: &SigPublic) -> Result<Vec<OutboundId>> {
        self.mutate_conference(|conference| {
            let messages = conference.evict(who)?;
            Ok(((), messages))
        })
        .map(|((), deliveries)| deliveries)
    }

    /// Leaves and durably queues the signed removal message.
    pub fn leave(&mut self) -> Result<Vec<OutboundId>> {
        self.mutate_conference(|conference| {
            let message = conference.leave()?;
            Ok(((), vec![message]))
        })
        .map(|((), deliveries)| deliveries)
    }

    /// Contributes fresh entropy and durably queues the resulting message.
    pub fn rekey(&mut self) -> Result<Vec<OutboundId>> {
        self.mutate_conference(|conference| {
            let messages = conference.rekey()?;
            Ok(((), messages))
        })
        .map(|((), deliveries)| deliveries)
    }

    /// Rotates prekeys, rekeys, and durably queues all resulting messages.
    pub fn heal(&mut self) -> Result<Vec<OutboundId>> {
        self.mutate_conference(|conference| {
            let messages = conference.heal()?;
            Ok(((), messages))
        })
        .map(|((), deliveries)| deliveries)
    }

    /// Durably advances the local prekey deadline clock.
    pub fn tick(&mut self) -> Result<()> {
        self.mutate_conference(|conference| {
            conference.tick();
            Ok(((), Vec::new()))
        })
        .map(|((), _)| ())
    }

    /// Atomically processes an inbound control payload and its transport ID.
    pub fn handle_inbound(&mut self, id: InboundId, payload: &[u8]) -> Result<InboundResult> {
        let digest = state::inbound_digest(payload);
        if let Some(committed) = self.state.inbound.get(&id) {
            if committed == &digest {
                return Ok(InboundResult {
                    duplicate: true,
                    events: Vec::new(),
                    deliveries: Vec::new(),
                });
            }
            return Err(Error::IdempotencyConflict { id });
        }
        self.commit_candidate(|candidate| {
            let (events, messages) = candidate.conference.handle(payload)?;
            let deliveries = candidate.enqueue(messages)?;
            candidate.record_inbound(id, digest);
            Ok(InboundResult {
                duplicate: false,
                events,
                deliveries,
            })
        })
    }

    /// Durably queues anti-entropy and any required node-key repair requests.
    pub fn resync(&mut self) -> Result<Vec<OutboundId>> {
        self.mutate_conference(|conference| Ok(((), conference.resync())))
            .map(|((), deliveries)| deliveries)
    }

    /// Protects one media frame and commits its sender counter before return.
    pub fn protect(&mut self, codec: Codec, frame: &[u8], keyframe: bool) -> Result<Vec<u8>> {
        self.mutate_conference(|conference| {
            Ok((conference.protect(codec, frame, keyframe)?, Vec::new()))
        })
        .map(|(protected, _)| protected)
    }

    /// Opens one media frame and commits ratchet/replay state before return.
    pub fn open_media(&mut self, packet: &[u8]) -> Result<(SigPublic, Vec<u8>)> {
        self.mutate_conference(|conference| Ok((conference.open(packet)?, Vec::new())))
            .map(|(opened, _)| opened)
    }

    /// Reads media routing metadata without mutating state.
    pub fn inspect(packet: &[u8]) -> Result<Trailer> {
        Ok(Conference::inspect(packet)?)
    }

    /// Returns all unacknowledged deliveries in monotonic ID order.
    pub fn pending_deliveries(&self) -> Vec<PendingDelivery> {
        self.state.outbox.values().cloned().collect()
    }

    /// Durably acknowledges one delivery; repeated acknowledgements return false.
    pub fn acknowledge(&mut self, id: OutboundId) -> Result<bool> {
        if !self.state.outbox.contains_key(&id) {
            return Ok(false);
        }
        self.commit_candidate(|candidate| Ok(candidate.outbox.remove(&id).is_some()))
    }

    /// Writes the current state as a snapshot and resets the WAL crash-safely.
    pub fn checkpoint(&mut self) -> Result<()> {
        let payload = self.state.encode()?;
        self.store.checkpoint(self.state.sequence, &payload)
    }

    fn mutate_conference<R>(
        &mut self,
        operation: impl FnOnce(&mut Conference) -> crate::Result<(R, Vec<crate::Message>)>,
    ) -> Result<(R, Vec<OutboundId>)> {
        self.commit_candidate(|candidate| {
            let (result, messages) = operation(&mut candidate.conference)?;
            let deliveries = candidate.enqueue(messages)?;
            Ok((result, deliveries))
        })
    }

    fn commit_candidate<R>(
        &mut self,
        operation: impl FnOnce(&mut LogicalState) -> Result<R>,
    ) -> Result<R> {
        let current_payload = self.state.encode()?;
        let mut candidate = LogicalState::decode(&current_payload, self.state.sequence)?;
        let result = operation(&mut candidate)?;
        candidate.sequence = candidate
            .sequence
            .checked_add(1)
            .ok_or(Error::LimitExceeded("transaction sequence exhausted"))?;
        let candidate_payload = candidate.encode()?;
        self.store.append(
            self.state.sequence,
            &current_payload,
            candidate.sequence,
            &candidate_payload,
            candidate.options,
        )?;
        self.state = candidate;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::store::Fault;
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "cfr-persistence-atomic-{}-{id}",
                std::process::id()
            )))
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn failed_sync_does_not_advance_live_or_recovered_state() {
        let directory = TestDirectory::new();
        let mut conference =
            PersistentConference::create(&directory.0, Policy::leaderless(2)).unwrap();
        let sequence = conference.sequence();
        let version = conference.version();
        conference.store.inject(Fault::BeforeSync);
        assert!(matches!(conference.tick(), Err(Error::Io(_))));
        assert_eq!(conference.sequence(), sequence);
        assert_eq!(conference.version(), version);
        drop(conference);

        let reopened = PersistentConference::open(&directory.0).unwrap();
        assert_eq!(reopened.sequence(), sequence);
        assert_eq!(reopened.version(), version);
    }
}
