// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Assumption A5: the encoding is injective.
//!
//! Stated as a property the fuzzer can refute: for every byte string the
//! decoder accepts, re-encoding must reproduce it exactly. If two byte strings
//! ever decoded to the same value, one of them would fail this, because only
//! one can be the encoder's output.

#![no_main]
use cfr_core::codec::{Reader, Writer};
use libfuzzer_sys::fuzz_target;

/// Decodes a self-describing value and re-encodes it.
fn round(data: &[u8]) -> Option<Vec<u8>> {
    let mut r = Reader::new(data);
    let mut w = Writer::new();
    // Try each shape in turn; the type tag makes the choice unambiguous.
    if let Ok(v) = r.bytes() {
        w.bytes(v);
    } else {
        let mut r = Reader::new(data);
        if let Ok(v) = r.u64() {
            w.u64(v);
            r.finish().ok()?;
            return Some(w.finish());
        }
        let mut r = Reader::new(data);
        if let Ok(v) = r.str() {
            w.str(v);
            r.finish().ok()?;
            return Some(w.finish());
        }
        let mut r = Reader::new(data);
        if let Ok(v) = r.set(|r| r.bytes()) {
            w.set(&v, |w, x| {
                w.bytes(x);
            });
            r.finish().ok()?;
            return Some(w.finish());
        }
        let mut r = Reader::new(data);
        if let Ok(v) = r.list(|r| r.bytes()) {
            w.list(&v, |w, x| {
                w.bytes(x);
            });
            r.finish().ok()?;
            return Some(w.finish());
        }
        return None;
    }
    r.finish().ok()?;
    Some(w.finish())
}

fuzz_target!(|data: &[u8]| {
    if let Some(again) = round(data) {
        assert_eq!(
            again,
            data,
            "an accepted encoding must be the encoder's own output"
        );
    }
});
