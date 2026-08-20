// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! A seeded, randomized state machine over the public API.
//!
//! Coverage-guided fuzzing lives in `fuzz/` and needs a nightly toolchain. This
//! suite runs everywhere, every time, and checks the invariants that matter
//! after each step. It is not a substitute for the fuzzer; it is the part of
//! fuzzing that can be a unit test.
//!
//! Every run is reproducible from its seed. A randomized failure nobody can
//! replay is a failure nobody will fix.

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

use cfr_protocol::{Codec, Policy};
use net::{Net, Rng};

const CODECS: [Codec; 7] = [
    Codec::H264,
    Codec::H265,
    Codec::Av1,
    Codec::Vp8,
    Codec::Vp9,
    Codec::Opus,
    Codec::Generic,
];

struct Checks {
    count: usize,
    known: std::collections::BTreeSet<cfr_protocol::SigPublic>,
}

impl Checks {
    /// Invariants that must hold after every step, whatever the schedule.
    fn run(&mut self, net: &mut Net, step: usize, seed: u64) {
        let online = net.online();

        // I1. A participant that can derive the current key can always
        // protect a frame.
        //
        // The converse is deliberately not asserted. A participant that has
        // fallen behind keeps sending under the last version it held, and
        // peers open it out of their overlap window. That is the behaviour
        // that keeps media flowing during a repair, and it costs nothing:
        // the retained key was already shared with exactly that membership.
        for id in &online {
            let ready = net.peers[id].ready();
            let codec = CODECS[step % CODECS.len()];
            let r = net
                .peers
                .get_mut(id)
                .unwrap()
                .protect(codec, b"invariant probe", false);
            if ready {
                assert!(
                    r.is_ok(),
                    "seed {seed} step {step}: derivable key but protection failed"
                );
            }
            self.count += 1;
        }

        // I2. Agreement, stated as an observable: anyone reporting the
        // sender's version must open the sender's frame. Version equality
        // without key equality is exactly the silent divergence the
        // construction is required to make impossible.
        if online.len() >= 2 {
            let sender = online[0];
            if net.peers[&sender].ready() {
                let sealed = net
                    .peers
                    .get_mut(&sender)
                    .unwrap()
                    .protect(Codec::Generic, b"agreement", false)
                    .unwrap();
                let sv = net.peers[&sender].version();
                for id in online.iter().skip(1) {
                    // Only meaningful when the receiver can derive its own
                    // current key. A receiver mid-repair knows the right
                    // version and not yet the key; that is a liveness state,
                    // not a disagreement, and the final convergence check is
                    // what holds it to account.
                    if net.peers[id].version() == sv && net.peers[id].ready() {
                        assert!(
                            net.peers.get_mut(id).unwrap().open(&sealed).is_ok(),
                            "seed {seed} step {step}: equal version, different key"
                        );
                        self.count += 1;
                    }
                }
            }
        }

        // I3. Replay is inert: re-delivering a message already processed must
        // not move the version.
        if let Some(id) = online.first() {
            let before = net.peers[id].version();
            let probe = net.peers.get_mut(id).unwrap().resync();
            for m in &probe {
                let _ = net.peers.get_mut(id).unwrap().handle(&m.payload);
            }
            assert_eq!(
                net.peers[id].version(),
                before,
                "seed {seed} step {step}: self-delivery moved the version"
            );
            self.count += 1;
        }

        // I4. No identity is ever counted as a member unless it really
        // exists. An identity that has been evicted may still appear in the
        // roster of a peer that has not yet seen the eviction, which is
        // correct; a roster entry nobody ever created is not.
        for id in &online {
            for m in net.peers[id].members() {
                assert!(
                    self.known.contains(&m),
                    "seed {seed} step {step}: roster names an identity nobody created"
                );
                self.count += 1;
            }
        }

        // I5. Retained state stays bounded.
        for id in &online {
            let b = net.peers[id].state_bytes();
            assert!(
                b < 4 * 1024 * 1024,
                "seed {seed} step {step}: state grew to {b} bytes"
            );
            self.count += 1;
        }
    }
}

fn one_run(seed: u64, steps: usize, checks: &mut Checks) {
    let pol = || Policy::leaderless(2);
    let (mut net, founder) = Net::founder(seed, pol());
    net.join(founder, pol());
    net.join(founder, pol());
    checks.known.extend(net.ids());
    let mut rng = Rng::new(seed ^ 0xA5A5);

    for step in 0..steps {
        let ids = net.ids();
        let online = net.online();
        let action = rng.below(12);
        match action {
            0..=2 => {
                if let Some(w) = rng.pick(&online) {
                    net.act(w, |c| c.rekey().unwrap_or_default());
                }
            }
            3 => {
                if let Some(w) = rng.pick(&online) {
                    net.act(w, |c| c.heal().unwrap_or_default());
                }
            }
            4 => {
                if ids.len() < 7 {
                    if let Some(w) = rng.pick(&online) {
                        net.try_join(w, pol());
                    }
                }
            }
            5 => {
                // Eviction needs a quorum of two distinct members.
                if online.len() >= 4 {
                    let target = online[rng.below(online.len())];
                    let voters: Vec<_> = online
                        .iter()
                        .copied()
                        .filter(|x| *x != target)
                        .take(2)
                        .collect();
                    for v in voters {
                        net.act(v, |c| c.evict(&target).unwrap_or_default());
                    }
                    // The evicted client stays reachable, as it would in a
                    // real call: it loses membership, not connectivity.
                    net.evicted.insert(target);
                }
            }
            6 => {
                if let Some(w) = rng.pick(&online) {
                    if net.offline.len() + 1 < ids.len() {
                        net.offline.insert(w);
                    }
                }
            }
            7 => {
                if let Some(w) = rng.pick(&ids) {
                    if net.offline.remove(&w) {
                        net.act(w, cfr_protocol::Conference::resync);
                        let others: Vec<_> = net.online();
                        for o in others {
                            net.act(o, cfr_protocol::Conference::resync);
                        }
                    }
                }
            }
            8 => {
                // Split the network, let both halves move, then heal.
                if online.len() >= 3 {
                    let cut = 1 + rng.below(online.len() - 1);
                    net.partitions = vec![
                        online[..cut].iter().copied().collect(),
                        online[cut..].iter().copied().collect(),
                    ];
                    if let Some(w) = rng.pick(&online) {
                        net.act(w, |c| c.rekey().unwrap_or_default());
                    }
                    net.partitions.clear();
                    for o in net.online() {
                        net.act(o, cfr_protocol::Conference::resync);
                    }
                    for o in net.online() {
                        net.act(o, cfr_protocol::Conference::resync);
                    }
                }
            }
            9 => {
                net.loss_percent = u64::try_from(rng.below(40)).unwrap();
                if let Some(w) = rng.pick(&online) {
                    net.act(w, |c| c.rekey().unwrap_or_default());
                }
                net.loss_percent = 0;
                for o in net.online() {
                    net.act(o, cfr_protocol::Conference::resync);
                }
            }
            10 => {
                if let Some(w) = rng.pick(&online) {
                    net.peers.get_mut(&w).unwrap().tick();
                }
            }
            _ => {
                // Feed a mutated real message to a random peer. It must be
                // rejected or ignored, never accepted.
                if let (Some(from), Some(to)) = (rng.pick(&online), rng.pick(&online)) {
                    let probe = net.peers.get_mut(&from).unwrap().resync();
                    if let Some(m) = probe.first() {
                        let mut bad = m.payload.clone();
                        if !bad.is_empty() {
                            let i = rng.below(bad.len());
                            bad[i] ^= 1 << rng.below(8);
                        }
                        let _ = net.peers.get_mut(&to).unwrap().handle(&bad);
                    }
                }
            }
        }
        checks.known.extend(net.ids());
        checks.run(&mut net, step, seed);
    }

    // Whatever happened, a full resynchronisation must bring everyone back to
    // one key. This is the liveness half; the invariants above are the safety
    // half.
    net.offline.clear();
    net.partitions.clear();
    net.loss_percent = 0;
    for _ in 0..3 {
        for o in net.online() {
            net.act(o, cfr_protocol::Conference::resync);
        }
    }
    if let Some(w) = net.online().first().copied() {
        net.act(w, |c| c.rekey().unwrap_or_default());
    }
    for _ in 0..2 {
        for o in net.online() {
            net.act(o, cfr_protocol::Conference::resync);
        }
    }
    net.assert_agreement(&format!("seed {seed}: convergence after the run"));
}

#[test]
fn randomized_state_machine() {
    let seeds: u64 = std::env::var("CFR_FUZZ_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(12);
    let steps: usize = std::env::var("CFR_FUZZ_STEPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(40);

    let mut checks = Checks {
        count: 0,
        known: std::collections::BTreeSet::new(),
    };
    for seed in 0..seeds {
        one_run(seed, steps, &mut checks);
    }
    println!(
        "randomized: {seeds} seeds x {steps} steps, {} checks",
        checks.count
    );
    assert!(checks.count > 0);
}

/// A single replayable seed, so a failure found by the sweep can be narrowed.
#[test]
fn randomized_single_seed() {
    let seed: u64 = std::env::var("CFR_FUZZ_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(99);
    let mut checks = Checks {
        count: 0,
        known: std::collections::BTreeSet::new(),
    };
    one_run(seed, 60, &mut checks);
}

/// Media protection under an arbitrary sequence of frames, codecs and losses.
#[test]
fn randomized_media() {
    let pol = || Policy::leaderless(2);
    let (mut net, a) = Net::founder(777, pol());
    let b = net.join(a, pol());
    let mut rng = Rng::new(4242);
    let mut delivered = 0usize;

    for round in 0..300 {
        if round % 50 == 49 {
            net.act(a, |c| c.rekey().unwrap_or_default());
        }
        let codec = CODECS[rng.below(CODECS.len())];
        let len = rng.below(200);
        let frame: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(31)).collect();
        let keyframe = rng.chance(20);

        let Ok(sealed) = net
            .peers
            .get_mut(&a)
            .unwrap()
            .protect(codec, &frame, keyframe)
        else {
            continue;
        };

        // A forwarder can always read the routing metadata.
        let t = cfr_protocol::Conference::inspect(&sealed).expect("inspectable");
        assert_eq!(t.codec, codec);

        if rng.chance(15) {
            continue; // lost in transit
        }
        match net.peers.get_mut(&b).unwrap().open(&sealed) {
            Ok((from, plain)) => {
                assert_eq!(from, a);
                assert_eq!(plain, frame, "codec {codec:?} round {round}");
                delivered += 1;
            }
            Err(e) => panic!("round {round}, codec {codec:?}: {e:?}"),
        }
    }
    assert!(delivered > 200, "only {delivered} frames delivered");
}

/// Mutating any single byte of a protected frame must be caught.
#[test]
fn media_mutation_is_always_caught() {
    let pol = || Policy::leaderless(2);
    let (mut net, a) = Net::founder(31, pol());
    let b = net.join(a, pol());
    let mut rng = Rng::new(31);
    let mut checked = 0usize;

    for _ in 0..40 {
        let codec = CODECS[rng.below(CODECS.len())];
        let frame: Vec<u8> = (0..64u8).collect();
        let sealed = net
            .peers
            .get_mut(&a)
            .unwrap()
            .protect(codec, &frame, true)
            .unwrap();
        for _ in 0..8 {
            let mut bad = sealed.clone();
            let i = rng.below(bad.len());
            bad[i] ^= 1 << rng.below(8);
            if bad == sealed {
                continue;
            }
            let r = net.peers.get_mut(&b).unwrap().open(&bad);
            match r {
                Err(_) => checked += 1,
                Ok((_, plain)) => {
                    // The only acceptable success is a byte-identical frame,
                    // which a one-bit mutation cannot produce.
                    assert_ne!(plain, frame, "mutation at {i} was not detected");
                    panic!("mutation at byte {i} produced a different accepted frame");
                }
            }
        }
    }
    assert!(checked > 250, "only {checked} mutations exercised");
}

/// Arbitrary bytes offered to the control plane must never panic.
#[test]
fn arbitrary_control_input_never_panics() {
    let pol = || Policy::leaderless(2);
    let (mut net, a) = Net::founder(5150, pol());
    let b = net.join(a, pol());
    let mut rng = Rng::new(5150);

    let seeds: Vec<Vec<u8>> = net
        .peers
        .get_mut(&a)
        .unwrap()
        .resync()
        .into_iter()
        .map(|m| m.payload)
        .collect();
    for _ in 0..3000 {
        let mut buf = if rng.chance(60) && !seeds.is_empty() {
            seeds[rng.below(seeds.len())].clone()
        } else {
            (0..rng.below(200))
                .map(|_| (rng.next() & 0xFF) as u8)
                .collect()
        };
        for _ in 0..1 + rng.below(4) {
            if buf.is_empty() {
                break;
            }
            let i = rng.below(buf.len());
            buf[i] ^= (rng.next() & 0xFF) as u8;
        }
        let _ = net.peers.get_mut(&b).unwrap().handle(&buf);
        let _ = net.peers.get_mut(&b).unwrap().open(&buf);
        let _ = cfr_protocol::Conference::inspect(&buf);
    }
    // The participant is still usable afterwards.
    assert!(net.peers[&b].members().contains(&a));
    let _ = net.peers.get_mut(&b).unwrap().rekey().unwrap();
}
