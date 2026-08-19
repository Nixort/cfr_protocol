// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Transport message parsing under arbitrary input.

#![no_main]
use cfr_core::Message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(m) = Message::from_wire(data) else {
        return;
    };
    assert_eq!(m.to_wire(), data, "non-canonical message accepted");
    assert_eq!(Message::from_wire(&m.to_wire()).unwrap(), m);
});
