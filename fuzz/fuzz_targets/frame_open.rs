// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Opening arbitrary media packets. Nothing may panic, and nothing that was
//! not produced by `protect` may be accepted.

#![no_main]
use cfr_crypto::{Secret, SigSecret};
use cfr_media::{Codec, Protector};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let a = SigSecret::from_seed(&[1u8; 32]).public();
    let b = SigSecret::from_seed(&[2u8; 32]).public();
    let key = Secret::from([7u8; 32]);
    let mut rx = Protector::new([0u8; 32], b, 4);
    rx.install([1u8; 8], &key, [a, b]);

    let _ = Protector::inspect(data);
    if let Ok((from, plain)) = rx.unprotect(data) {
        // Anything accepted must have come from a real participant and must
        // round-trip through the sender.
        assert_eq!(from, a);
        let mut tx = Protector::new([0u8; 32], a, 4);
        tx.install([1u8; 8], &key, [a, b]);
        let _ = tx.protect(Codec::Generic, &plain, false);
    }
});
