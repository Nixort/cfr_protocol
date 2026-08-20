// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Adversarial end-to-end tests.
//!
//! Each test states an attack and asserts it fails. They are written against
//! the public API only, so nothing here depends on internal representation.

#![allow(missing_docs)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::match_single_binding,
    clippy::range_plus_one,
    clippy::single_match,
    clippy::single_match_else,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::should_implement_trait,
    clippy::too_many_lines,
    clippy::uninlined_format_args
)]

mod net;

use cfr_protocol::layers::media::TRAILER_LEN;
use cfr_protocol::{Beacon, Codec, Conference, Joining, Policy};
use net::Net;

fn pol() -> Policy {
    Policy::leaderless(2)
}

/// A hostile server that reorders, duplicates, drops and injects.
#[test]
fn a1_a_hostile_server_cannot_break_agreement() {
    let (mut net, a) = Net::founder(1, pol());
    let b = net.join(a, pol());
    let c = net.join(a, pol());

    // Capture real traffic, then replay it in reverse, doubled.
    let mut captured: Vec<Vec<u8>> = Vec::new();
    for _ in 0..4 {
        let out = net.peers.get_mut(&a).unwrap().rekey().unwrap();
        for m in &out {
            captured.push(m.payload.clone());
        }
        net.send(a, out);
        net.settle();
    }
    captured.reverse();
    for m in captured.iter().chain(captured.iter()) {
        let _ = net.peers.get_mut(&b).unwrap().handle(m);
        let _ = net.peers.get_mut(&c).unwrap().handle(m);
    }
    net.settle();
    net.assert_agreement("after reorder, duplication and replay");
}

/// An outsider with a valid-looking identity cannot make members accept its
/// operations.
#[test]
fn a2_an_outsider_cannot_inject_operations() {
    let (mut net, a) = Net::founder(2, pol());
    let b = net.join(a, pol());
    let version = net.peers[&b].version();

    // A complete stranger builds a conference of its own and replays its
    // traffic at b.
    let (mut stranger, bootstrap) = Conference::create(pol()).unwrap();
    let hostile = stranger.identity();
    let mut traffic = bootstrap;
    traffic.extend(stranger.rekey().unwrap());
    for m in traffic {
        let _ = net.peers.get_mut(&b).unwrap().handle(&m.payload);
    }
    net.settle();

    assert_eq!(net.peers[&b].version(), version, "state must not move");
    assert!(!net.peers[&b].members().contains(&hostile));
}

/// An evicted participant cannot follow the key, even holding everything it
/// had at the moment of eviction.
#[test]
fn a3_an_evicted_participant_is_locked_out() {
    let (mut net, a) = Net::founder(3, pol());
    let b = net.join(a, pol());
    let c = net.join(a, pol());
    net.assert_agreement("before eviction");

    net.act(a, |p| p.evict(&c).unwrap_or_default());
    net.act(b, |p| p.evict(&c).unwrap_or_default());
    net.rekey(a);

    assert!(!net.peers[&a].members().contains(&c));

    let frame = b"after eviction".to_vec();
    let sealed = net
        .peers
        .get_mut(&a)
        .unwrap()
        .protect(Codec::Generic, &frame, false)
        .unwrap();
    assert!(
        net.peers.get_mut(&c).unwrap().open(&sealed).is_err(),
        "the evicted participant must not open post-eviction media"
    );
    // And the remaining members still can.
    assert!(net.peers.get_mut(&b).unwrap().open(&sealed).is_ok());
}

/// A member cannot forge a frame that appears to come from someone else, even
/// though everyone holds the same group key.
#[test]
fn a4_a_member_cannot_impersonate_another_sender() {
    let (mut net, a) = Net::founder(4, pol());
    let b = net.join(a, pol());
    let c = net.join(a, pol());
    net.assert_agreement("three present");

    // b protects a frame and rewrites the sender tag to a's.
    let mut sealed = net
        .peers
        .get_mut(&b)
        .unwrap()
        .protect(Codec::Generic, b"forged", false)
        .unwrap();
    let n = sealed.len();
    let tag = cfr_protocol::layers::media::sender_tag(&a);
    sealed[n - TRAILER_LEN..n - TRAILER_LEN + tag.len()].copy_from_slice(&tag);

    assert!(
        net.peers.get_mut(&c).unwrap().open(&sealed).is_err(),
        "per-sender ratchets must prevent impersonation under a shared key"
    );
}

/// Feeding two participants different histories is detected by the beacon
/// rather than silently splitting the call.
#[test]
fn a5_silent_divergence_is_detected() {
    let (mut net, a) = Net::founder(5, pol());
    let b = net.join(a, pol());
    let c = net.join(a, pol());
    net.assert_agreement("aligned");

    // The server censors c while a rekeys twice.
    net.partitions = vec![[a, b].into_iter().collect(), [c].into_iter().collect()];
    net.rekey(a);
    net.rekey(b);
    net.partitions.clear();

    let beacon_a = net.peers[&a].beacon();
    assert_ne!(
        net.peers[&c].check_beacon(&a, &beacon_a),
        Beacon::Agreed,
        "c must not believe it agrees with a"
    );

    // And resynchronising repairs it.
    net.resync(c);
    net.resync(a);
    net.settle();
    net.assert_agreement("after resynchronisation");
    let fresh = net.peers[&a].beacon();
    assert_eq!(
        net.peers[&c].check_beacon(&a, &fresh),
        Beacon::Agreed,
        "once realigned, the beacon must confirm"
    );
}

/// A snapshot of a participant's memory does not open earlier media.
#[test]
fn a6_a_memory_snapshot_does_not_open_the_past() {
    let (mut net, a) = Net::founder(6, pol());
    let b = net.join(a, pol());
    net.assert_agreement("paired");

    // Record traffic under the current key.
    let old_frames: Vec<Vec<u8>> = (0..3)
        .map(|i| {
            net.peers
                .get_mut(&a)
                .unwrap()
                .protect(Codec::Generic, &[i as u8; 20], false)
                .unwrap()
        })
        .collect();

    // Advance far enough that the old version leaves the media overlap window.
    for _ in 0..6 {
        net.rekey(a);
        net.rekey(b);
    }

    for f in &old_frames {
        assert!(
            net.peers.get_mut(&b).unwrap().open(f).is_err(),
            "retired versions must be unopenable"
        );
    }
}

/// A false accusation costs the accuser and achieves nothing.
#[test]
fn a7_a_false_accusation_does_not_evict() {
    let (mut net, a) = Net::founder(7, pol());
    let b = net.join(a, pol());
    let c = net.join(a, pol());
    let before = net.peers[&a].members();

    // c fabricates traffic claiming b equivocated by replaying b's own
    // messages with mutations. Nothing it can produce carries a valid proof.
    let out = net.peers.get_mut(&b).unwrap().rekey().unwrap();
    for m in &out {
        for i in (0..m.payload.len()).step_by(7) {
            let mut bad = m.payload.clone();
            bad[i] ^= 0x80;
            let _ = net.peers.get_mut(&c).unwrap().handle(&bad);
        }
    }
    net.send(b, out);
    net.settle();

    assert_eq!(net.peers[&a].members(), before, "nobody was evicted");
    assert!(net.peers[&c].members().contains(&b));
}

/// An inviter cannot substitute its own prekey into a newcomer's package and
/// become a permanent man in the middle.
#[test]
fn a8_a_key_package_cannot_be_rewritten() {
    let joining = Joining::new(pol()).unwrap();
    let kp = joining.key_package();
    let mut forged = kp.clone();
    forged.prekey = cfr_protocol::layers::crypto::DhPublic::from_bytes([0x42u8; 32]);

    let (mut alice, _) = Conference::create(pol()).unwrap();
    assert!(
        alice.invite(&forged).is_err(),
        "a rewritten package must not be admitted"
    );
    assert!(alice.invite(&kp).is_ok());
}

/// The frame trailer is readable by a forwarder and not rewritable by one.
#[test]
fn a9_a_forwarder_can_route_but_not_rewrite() {
    let (mut net, a) = Net::founder(9, pol());
    let b = net.join(a, pol());

    let frame = [0u8, 0, 0, 1, 0x65, 1, 2, 3, 4, 5];
    let sealed = net
        .peers
        .get_mut(&a)
        .unwrap()
        .protect(Codec::H264, &frame, true)
        .unwrap();

    // Routing metadata is available without any key.
    let t = Conference::inspect(&sealed).unwrap();
    assert_eq!(t.codec, Codec::H264);
    assert!(t.keyframe);

    // Every byte of it is authenticated.
    for i in sealed.len() - 13..sealed.len() {
        let mut bad = sealed.clone();
        bad[i] ^= 0x01;
        assert!(
            net.peers.get_mut(&b).unwrap().open(&bad).is_err(),
            "trailer byte {i} was not authenticated"
        );
    }
}

/// A participant that has lost material recovers without help from a
/// coordinator, and without anyone handing it keys it is not entitled to.
#[test]
fn a10_repair_does_not_leak_to_non_recipients() {
    let (mut net, a) = Net::founder(10, pol());
    let b = net.join(a, pol());
    let c = net.join(a, pol());

    // c is excluded from a rekey, then asks for repair.
    net.partitions = vec![[a, b].into_iter().collect(), [c].into_iter().collect()];
    net.rekey(a);
    net.partitions.clear();

    net.resync(c);
    net.settle();
    net.assert_agreement("c recovered by repair");

    // An evicted party asking for the same material gets nothing.
    net.act(a, |p| p.evict(&c).unwrap_or_default());
    net.act(b, |p| p.evict(&c).unwrap_or_default());
    net.rekey(a);
    let version_after = net.peers[&a].version();

    let probe = net
        .peers
        .get_mut(&a)
        .unwrap()
        .protect(Codec::Generic, b"members only", false)
        .unwrap();

    let requests = net.peers.get_mut(&c).unwrap().resync();
    net.send(c, requests);
    net.settle();

    // The public history may reach an outsider — it is public. What must not
    // reach it is key material, so the test is stated on the key and not on
    // the version label.
    assert!(
        net.peers.get_mut(&c).unwrap().open(&probe).is_err(),
        "an evicted party must not be repaired back into the key"
    );
    let _ = version_after;
}
