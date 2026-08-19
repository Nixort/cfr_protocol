// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Integration tests: real conferences, real messages, no internal access.

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

mod harness;

use cfr_core::{Beacon, Message, Policy};
use harness::Net;

fn policy() -> Policy {
    Policy::leaderless(2)
}

#[test]
fn founder_alone_has_a_key() {
    let (net, a) = Net::founder(policy());
    assert!(net.get(&a).group_key().is_some());
    assert_eq!(net.get(&a).members().len(), 1);
}

#[test]
fn two_participants_agree() {
    let (mut net, a) = Net::founder(policy());
    let b = net.join(a, policy());
    net.assert_agreement("after join");
    assert_eq!(net.get(&a).members().len(), 2);
    assert!(net.get(&b).members().contains(&a));
}

#[test]
fn ten_participants_agree_and_keep_agreeing() {
    let (mut net, a) = Net::founder(policy());
    let mut ids = vec![a];
    for _ in 0..9 {
        ids.push(net.join(a, policy()));
        net.assert_agreement("during growth");
    }
    assert_eq!(net.get(&a).members().len(), 10);

    // Everyone contributes in turn; the key must move and stay agreed.
    let mut seen = std::collections::BTreeSet::new();
    for id in &ids {
        net.contribute(*id);
        net.assert_agreement("after contribution");
        seen.insert(net.get(&a).version());
    }
    assert!(seen.len() >= 5, "the key must actually change");
}

#[test]
fn any_participant_can_initiate_there_is_no_leader() {
    let (mut net, a) = Net::founder(policy());
    let b = net.join(a, policy());
    let c = net.join(b, policy()); // invited by a non-founder
    net.assert_agreement("invited by a non-founder");
    assert_eq!(net.get(&c).members().len(), 3);

    // The founder can go away entirely and the rest still rekey.
    net.act(a, |p| p.leave().map(|o| vec![o]).unwrap_or_default());
    net.contribute(b);
    net.settle();
    assert!(!net.get(&b).members().contains(&a));
    assert!(net.get(&b).group_key().is_some());
    assert!(net.get(&c).group_key().is_some());
}

#[test]
fn key_changes_on_every_contribution() {
    let (mut net, a) = Net::founder(policy());
    let b = net.join(a, policy());
    let k0 = net.get(&a).group_key().unwrap();
    net.contribute(b);
    let k1 = net.get(&a).group_key().unwrap();
    assert_ne!(k0.as_bytes(), k1.as_bytes());
    net.assert_agreement("after b contributes");
}

#[test]
fn removed_participant_loses_the_key() {
    let (mut net, a) = Net::founder(policy());
    let b = net.join(a, policy());
    let c = net.join(a, policy());
    net.assert_agreement("before removal");

    let before = net.get(&c).group_key().unwrap();

    // Quorum of two: a and b both evict c.
    net.remove(a, c);
    net.remove(b, c);
    net.settle();

    assert!(!net.get(&a).members().contains(&c));
    assert!(
        net.get(&a).removal_complete(&c),
        "a contribution excluding c must have entered the frontier"
    );

    let after = net.get(&a).group_key().unwrap();
    assert_ne!(after.as_bytes(), before.as_bytes());

    // c may still hold its own last key, but it is not the group's.
    let stale = net.get(&c).group_key();
    assert_ne!(
        stale.map(|k| *k.as_bytes()),
        Some(*after.as_bytes()),
        "evicted participant must not derive the live key"
    );
}

#[test]
fn offline_member_returns_and_catches_up() {
    let (mut net, a) = Net::founder(policy());
    let b = net.join(a, policy());
    let c = net.join(a, policy());
    net.assert_agreement("all present");

    net.offline.insert(c);
    for _ in 0..3 {
        net.contribute(a);
        net.contribute(b);
    }
    assert_ne!(
        net.get(&c).version(),
        net.get(&a).version(),
        "the absent member should be behind"
    );

    net.offline.remove(&c);
    net.repair(c);
    net.settle();

    assert_eq!(net.get(&c).version(), net.get(&a).version());
    net.assert_agreement("after catch-up");
}

#[test]
fn sync_advertises_causal_heads_instead_of_full_history() {
    let (mut net, a) = Net::founder(policy());
    let b = net.join(a, policy());
    for _ in 0..24 {
        net.contribute(a);
        net.contribute(b);
    }
    let history = net.get(&a).history_len();
    let request = net.get(&a).sync_request();
    let Message::Sync { heads, .. } = Message::from_wire(&request.payload).expect("sync frame")
    else {
        panic!("sync_request must emit Message::Sync");
    };

    assert!(!heads.is_empty());
    assert!(
        heads.len() < history,
        "causal heads must be smaller than full retained history"
    );
    assert!(
        request.payload.len() < history * 32,
        "repair advertisement must avoid a full OID list"
    );
}

#[test]
fn partition_heals_into_one_key() {
    let (mut net, a) = Net::founder(policy());
    let b = net.join(a, policy());
    let c = net.join(a, policy());
    let d = net.join(a, policy());
    net.assert_agreement("before the split");

    net.partitions = vec![[a, b].into_iter().collect(), [c, d].into_iter().collect()];
    net.contribute(a);
    net.contribute(c);

    assert_ne!(
        net.get(&a).version(),
        net.get(&c).version(),
        "the two sides must diverge while split"
    );

    net.partitions.clear();
    net.repair(a);
    net.repair(c);
    net.settle();
    net.repair(b);
    net.repair(d);
    net.settle();

    net.assert_agreement("after the partition heals");
}

#[test]
fn beacon_detects_agreement_and_ignorance() {
    let (mut net, a) = Net::founder(policy());
    let b = net.join(a, policy());
    net.assert_agreement("paired");

    let beacon_b = net.get(&b).beacon();
    assert_eq!(net.get(&a).check_beacon(&b, &beacon_b), Beacon::Agreed);

    // A beacon for a version a has never held is unknown, not agreed.
    let mut alien = beacon_b;
    alien[0] ^= 0xFF;
    assert_eq!(net.get(&a).check_beacon(&b, &alien), Beacon::Unknown);
}

#[test]
fn beacon_flags_a_forged_tag_as_divergence() {
    let (mut net, a) = Net::founder(policy());
    let b = net.join(a, policy());
    let mut forged = net.get(&b).beacon();
    forged[8] ^= 0x01; // same version, wrong key
    assert_eq!(net.get(&a).check_beacon(&b, &forged), Beacon::Diverged);
}

#[test]
fn replayed_messages_change_nothing() {
    let (mut net, a) = Net::founder(policy());
    let b = net.join(a, policy());
    net.contribute(a);
    let before = net.get(&b).group_key().unwrap();
    let version_before = net.get(&b).version();

    // Replay the entire history at b, twice.
    let history: Vec<Vec<u8>> = {
        let p = net.get(&a);
        let mut v = Vec::new();
        for _ in 0..2 {
            v.push(p.sync_request().payload.clone());
        }
        v
    };
    for h in history {
        let _ = net.members.get_mut(&b).unwrap().handle(&h);
    }
    net.settle();

    assert_eq!(net.get(&b).version(), version_before);
    assert_eq!(
        net.get(&b).group_key().unwrap().as_bytes(),
        before.as_bytes()
    );
}

#[test]
fn garbage_input_is_rejected_without_state_change() {
    let (mut net, a) = Net::founder(policy());
    let b = net.join(a, policy());
    let version = net.get(&b).version();
    let key = net.get(&b).group_key().unwrap();

    let mut inputs: Vec<Vec<u8>> = vec![
        vec![],
        vec![0u8; 1],
        vec![0xFFu8; 64],
        vec![1, 2, 3, 4, 5, 6, 7, 8],
    ];
    // Also every single-byte mutation of a real message.
    let real = net.get(&a).sync_request().payload;
    for i in 0..real.len().min(200) {
        let mut m = real.clone();
        m[i] ^= 0xFF;
        inputs.push(m);
    }

    for inp in inputs {
        let _ = net.members.get_mut(&b).unwrap().handle(&inp);
    }
    assert_eq!(net.get(&b).version(), version);
    assert_eq!(net.get(&b).group_key().unwrap().as_bytes(), key.as_bytes());
}

#[test]
fn rotation_then_contribution_heals_a_snapshot() {
    // Post-compromise security in the shape the library actually offers: after
    // rotating a prekey and contributing once, the group key no longer depends
    // on anything a past snapshot contained.
    let (mut net, a) = Net::founder(policy());
    let b = net.join(a, policy());
    let c = net.join(a, policy());
    net.assert_agreement("before compromise");

    let compromised = net.get(&b).group_key().unwrap();

    net.rotate(b);
    net.contribute(b);
    net.settle();

    let healed = net.get(&b).group_key().unwrap();
    assert_ne!(healed.as_bytes(), compromised.as_bytes());
    net.assert_agreement("after healing");
    assert!(net.get(&c).group_key().is_some());
}

#[test]
fn concurrent_contributions_merge_rather_than_conflict() {
    let (mut net, a) = Net::founder(policy());
    let b = net.join(a, policy());
    let c = net.join(a, policy());

    // Split so all three contribute without seeing each other.
    net.partitions = vec![
        [a].into_iter().collect(),
        [b].into_iter().collect(),
        [c].into_iter().collect(),
    ];
    net.contribute(a);
    net.contribute(b);
    net.contribute(c);
    net.partitions.clear();

    for id in [a, b, c] {
        net.repair(id);
    }
    net.settle();
    for id in [a, b, c] {
        net.repair(id);
    }
    net.settle();

    net.assert_agreement("three concurrent contributions merged");
    assert!(
        net.get(&a).frontier().len() >= 2,
        "concurrent contributions should widen the frontier"
    );
}

#[test]
fn state_stays_bounded_under_churn() {
    let (mut net, a) = Net::founder(policy());
    let b = net.join(a, policy());
    let c = net.join(a, policy());
    let mut peak = 0usize;
    for round in 0..40 {
        net.contribute(if round % 3 == 0 {
            a
        } else if round % 3 == 1 {
            b
        } else {
            c
        });
        peak = peak.max(net.get(&a).state_bytes());
    }
    net.assert_agreement("after sustained churn");
    assert!(
        peak < 512 * 1024,
        "retained state should plateau, saw {peak} bytes"
    );
}
