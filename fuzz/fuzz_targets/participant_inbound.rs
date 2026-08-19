// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Arbitrary bytes offered to a live participant.
//!
//! The participant must survive anything: no panic, no unbounded allocation,
//! and — the property that matters — no state change from input it rejected.

#![no_main]
use cfr_core::{Participant, Policy};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn fresh() -> Participant {
    static SEED: OnceLock<()> = OnceLock::new();
    SEED.get_or_init(|| ());
    let (p, _) = Participant::create(Policy::leaderless(2)).expect("created");
    p
}

fuzz_target!(|chunks: Vec<Vec<u8>>| {
    if chunks.len() > 64 {
        return;
    }
    let mut p = fresh();
    let before_members = p.members();
    let before_version = p.version();
    let mut accepted = false;

    for c in &chunks {
        if c.len() > 1 << 16 {
            continue;
        }
        if p.handle(c).is_ok() {
            accepted = true;
        }
    }

    if !accepted {
        assert_eq!(p.members(), before_members, "rejected input moved the roster");
        assert_eq!(p.version(), before_version, "rejected input moved the version");
    }
    // The participant remains usable.
    assert!(p.members().contains(&p.identity()));
});
