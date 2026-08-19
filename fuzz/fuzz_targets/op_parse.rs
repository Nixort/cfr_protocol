// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Operation parsing: never panic, and never accept two encodings of one
//! operation.

#![no_main]
use cfr_core::Op;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(op) = Op::from_wire(data) else { return };

    // Canonicity: an accepted operation re-encodes to exactly its input.
    assert_eq!(op.to_wire(), data, "non-canonical operation accepted");

    // The identifier is stable and covers the signature.
    let id = op.oid();
    assert_eq!(id, Op::from_wire(data).unwrap().oid());

    // Verification must be total: it decides, it does not panic.
    let _ = op.verify();
});
