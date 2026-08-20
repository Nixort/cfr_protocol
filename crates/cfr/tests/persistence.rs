// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Real-filesystem restart tests for the public persistence boundary.

#![allow(missing_docs)]

use cfr::persistence::{
    Error, InboundId, PendingDelivery, PersistenceOptions, PersistentConference,
};
use cfr::{Codec, Joining, Policy, Recipient, SigPublic};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "cfr-persistence-{label}-{}-{id}",
            std::process::id()
        )))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn policy() -> Policy {
    Policy::leaderless(2)
}

fn inbound_id(delivery: &PendingDelivery) -> InboundId {
    InboundId::from_bytes(*delivery.delivery_key.as_bytes())
}

fn acknowledge_all(conference: &mut PersistentConference) {
    let deliveries = conference.pending_deliveries();
    for delivery in deliveries {
        assert!(conference.acknowledge(delivery.id).unwrap());
    }
}

fn deliver(source: &mut PersistentConference, target: &mut PersistentConference) -> usize {
    let source_identity = source.identity();
    let target_identity = target.identity();
    let deliveries = source.pending_deliveries();
    let mut delivered = 0;
    for delivery in deliveries {
        let addressed = match delivery.recipient {
            Recipient::Everyone => source_identity != target_identity,
            Recipient::Peer(peer) => peer == target_identity,
        };
        if !addressed {
            continue;
        }
        target
            .handle_inbound(inbound_id(&delivery), &delivery.payload)
            .unwrap();
        assert!(source.acknowledge(delivery.id).unwrap());
        delivered += 1;
    }
    delivered
}

fn settle(alice: &mut PersistentConference, bob: &mut PersistentConference) {
    for _ in 0..256 {
        let delivered = deliver(alice, bob) + deliver(bob, alice);
        if delivered == 0 {
            return;
        }
    }
    panic!("persistent protocol flow did not settle");
}

fn pair(alice_path: &Path, bob_path: &Path) -> (PersistentConference, PersistentConference) {
    pair_with_bob_options(alice_path, bob_path, PersistenceOptions::default())
}

fn pair_with_bob_options(
    alice_path: &Path,
    bob_path: &Path,
    bob_options: PersistenceOptions,
) -> (PersistentConference, PersistentConference) {
    let mut alice = PersistentConference::create(alice_path, policy()).unwrap();
    acknowledge_all(&mut alice);
    let joining = Joining::new(policy()).unwrap();
    let bob_identity = joining.identity();
    alice.invite(&joining.key_package()).unwrap();
    let welcome = alice
        .pending_deliveries()
        .into_iter()
        .find(|delivery| delivery.recipient == Recipient::Peer(bob_identity))
        .expect("invite transaction must durably queue a welcome");
    let mut bob =
        PersistentConference::join_with_options(bob_path, joining, &welcome.payload, bob_options)
            .unwrap();
    assert!(alice.acknowledge(welcome.id).unwrap());
    settle(&mut alice, &mut bob);
    bob.rekey().unwrap();
    settle(&mut alice, &mut bob);
    assert_eq!(alice.version(), bob.version());
    (alice, bob)
}

#[test]
fn create_shutdown_open_preserves_identity_session_and_state() {
    let directory = TestDirectory::new("create-open");
    let conference = PersistentConference::create(directory.path(), policy()).unwrap();
    let identity = conference.identity();
    let session = conference.session_id();
    let members = conference.members();
    let version = conference.version();
    let sequence = conference.sequence();
    drop(conference);

    let reopened = PersistentConference::open(directory.path()).unwrap();
    assert_eq!(reopened.identity(), identity);
    assert_eq!(reopened.session_id(), session);
    assert_eq!(reopened.members(), members);
    assert_eq!(reopened.version(), version);
    assert_eq!(reopened.sequence(), sequence);
}

#[test]
fn unacknowledged_outbox_is_stable_across_restart_and_ack_is_durable() {
    let directory = TestDirectory::new("outbox");
    let mut conference = PersistentConference::create(directory.path(), policy()).unwrap();
    acknowledge_all(&mut conference);
    conference.rekey().unwrap();
    let pending = conference.pending_deliveries();
    assert!(!pending.is_empty());
    drop(conference);

    let mut reopened = PersistentConference::open(directory.path()).unwrap();
    assert_eq!(reopened.pending_deliveries(), pending);
    let acknowledged = pending[0].id;
    assert!(reopened.acknowledge(acknowledged).unwrap());
    assert!(!reopened.acknowledge(acknowledged).unwrap());
    drop(reopened);

    let reopened = PersistentConference::open(directory.path()).unwrap();
    assert!(reopened
        .pending_deliveries()
        .iter()
        .all(|delivery| delivery.id != acknowledged));
}

#[test]
fn inbound_dedup_and_conflict_survive_restart_without_new_output() {
    let alice_directory = TestDirectory::new("dedup-alice");
    let bob_directory = TestDirectory::new("dedup-bob");
    let (mut alice, mut bob) = pair(alice_directory.path(), bob_directory.path());
    alice.rekey().unwrap();
    let delivery = alice
        .pending_deliveries()
        .into_iter()
        .find(|delivery| delivery.recipient == Recipient::Everyone)
        .unwrap();
    let id = inbound_id(&delivery);
    let first = bob.handle_inbound(id, &delivery.payload).unwrap();
    assert!(!first.duplicate);
    let sequence = bob.sequence();
    let outbox = bob.pending_deliveries();
    drop(bob);

    let mut bob = PersistentConference::open(bob_directory.path()).unwrap();
    let duplicate = bob.handle_inbound(id, &delivery.payload).unwrap();
    assert!(duplicate.duplicate);
    assert!(duplicate.events.is_empty());
    assert!(duplicate.deliveries.is_empty());
    assert_eq!(bob.sequence(), sequence);
    assert_eq!(bob.pending_deliveries(), outbox);

    let mut conflicting = delivery.payload.clone();
    conflicting.push(0);
    assert!(matches!(
        bob.handle_inbound(id, &conflicting),
        Err(Error::IdempotencyConflict { id: conflict }) if conflict == id
    ));
    assert_eq!(bob.sequence(), sequence);
    assert_eq!(bob.pending_deliveries(), outbox);
}

#[test]
fn control_flow_and_media_ratchets_continue_across_restart() {
    let alice_directory = TestDirectory::new("flow-alice");
    let bob_directory = TestDirectory::new("flow-bob");
    let (mut alice, mut bob) = pair(alice_directory.path(), bob_directory.path());

    let first = alice.protect(Codec::Generic, b"frame zero", false).unwrap();
    assert_eq!(PersistentConference::inspect(&first).unwrap().counter, 0);
    let opened = bob.open_media(&first).unwrap();
    assert_eq!(opened.0, alice.identity());
    assert_eq!(opened.1, b"frame zero");
    drop(alice);
    drop(bob);

    let mut alice = PersistentConference::open(alice_directory.path()).unwrap();
    let mut bob = PersistentConference::open(bob_directory.path()).unwrap();
    assert!(
        bob.open_media(&first).is_err(),
        "media replay must survive restart"
    );
    let second = alice.protect(Codec::Generic, b"frame one", false).unwrap();
    assert_eq!(PersistentConference::inspect(&second).unwrap().counter, 1);
    assert_eq!(bob.open_media(&second).unwrap().1, b"frame one");

    bob.rekey().unwrap();
    settle(&mut alice, &mut bob);
    drop(alice);
    let mut alice = PersistentConference::open(alice_directory.path()).unwrap();
    alice.rekey().unwrap();
    settle(&mut alice, &mut bob);
    assert_eq!(alice.version(), bob.version());
    let post_restart = alice
        .protect(Codec::Generic, b"after restart", false)
        .unwrap();
    assert_eq!(bob.open_media(&post_restart).unwrap().1, b"after restart");
}

#[test]
fn one_directory_has_one_writer() {
    let directory = TestDirectory::new("lock");
    let first = PersistentConference::create(directory.path(), policy()).unwrap();
    assert!(matches!(
        PersistentConference::open(directory.path()),
        Err(Error::Locked)
    ));
    drop(first);
    assert!(PersistentConference::open(directory.path()).is_ok());
}

#[test]
fn open_never_silently_creates_missing_state() {
    let directory = TestDirectory::new("missing");
    assert!(matches!(
        PersistentConference::open(directory.path()),
        Err(Error::NotFound)
    ));
    assert!(!directory.path().exists());
}

#[test]
fn identities_remain_distinct_across_persistent_join() {
    let alice_directory = TestDirectory::new("identity-alice");
    let bob_directory = TestDirectory::new("identity-bob");
    let (alice, bob) = pair(alice_directory.path(), bob_directory.path());
    let identities: std::collections::BTreeSet<SigPublic> =
        [alice.identity(), bob.identity()].into_iter().collect();
    assert_eq!(identities.len(), 2);
    assert_eq!(alice.session_id(), bob.session_id());
}

#[test]
fn outbox_exhaustion_fails_before_protocol_or_sequence_commit() {
    let directory = TestDirectory::new("outbox-limit");
    let options = PersistenceOptions {
        max_outbox_entries: 3,
        ..PersistenceOptions::default()
    };
    let mut conference =
        PersistentConference::create_with_options(directory.path(), policy(), options).unwrap();
    assert_eq!(conference.pending_deliveries().len(), 3);
    acknowledge_all(&mut conference);
    for _ in 0..3 {
        conference.rekey().unwrap();
    }
    let sequence = conference.sequence();
    let version = conference.version();
    let pending = conference.pending_deliveries();
    assert!(matches!(
        conference.rekey(),
        Err(Error::LimitExceeded("durable outbox is full"))
    ));
    assert_eq!(conference.sequence(), sequence);
    assert_eq!(conference.version(), version);
    assert_eq!(conference.pending_deliveries(), pending);
    drop(conference);

    let reopened = PersistentConference::open(directory.path()).unwrap();
    assert_eq!(reopened.sequence(), sequence);
    assert_eq!(reopened.version(), version);
    assert_eq!(reopened.pending_deliveries(), pending);
}

#[test]
fn inbound_idempotency_eviction_is_bounded_and_durable() {
    let alice_directory = TestDirectory::new("window-alice");
    let bob_directory = TestDirectory::new("window-bob");
    let options = PersistenceOptions {
        inbound_window: 2,
        ..PersistenceOptions::default()
    };
    let (mut alice, mut bob) =
        pair_with_bob_options(alice_directory.path(), bob_directory.path(), options);
    let mut first = None;
    for index in 0..3 {
        alice.rekey().unwrap();
        let delivery = alice
            .pending_deliveries()
            .into_iter()
            .find(|delivery| delivery.recipient == Recipient::Everyone)
            .unwrap();
        let result = bob
            .handle_inbound(inbound_id(&delivery), &delivery.payload)
            .unwrap();
        assert!(!result.duplicate);
        assert!(alice.acknowledge(delivery.id).unwrap());
        if index == 0 {
            first = Some(delivery);
        }
    }
    let first = first.unwrap();
    let before = bob.sequence();
    let replay_after_eviction = bob
        .handle_inbound(inbound_id(&first), &first.payload)
        .unwrap();
    assert!(!replay_after_eviction.duplicate);
    assert_eq!(bob.sequence(), before + 1);
    drop(bob);

    let mut bob = PersistentConference::open(bob_directory.path()).unwrap();
    let durable_duplicate = bob
        .handle_inbound(inbound_id(&first), &first.payload)
        .unwrap();
    assert!(durable_duplicate.duplicate);
}
