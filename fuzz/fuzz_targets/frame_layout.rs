// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Codec partitioning: the clear and secret ranges must tile the frame exactly.
//!
//! A gap would leave content readable. An overlap would encrypt bytes twice and
//! corrupt the frame. Both are silent failures, which is why this is the
//! property that gets fuzzed rather than a set of hand-written examples.

#![no_main]
use cfr_media::{layout, Codec};
use libfuzzer_sys::fuzz_target;

const CODECS: [Codec; 7] = [
    Codec::H264,
    Codec::H265,
    Codec::Av1,
    Codec::Vp8,
    Codec::Vp9,
    Codec::Opus,
    Codec::Generic,
];

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let codec = CODECS[usize::from(data[0]) % CODECS.len()];
    let keyframe = data[0] & 0x80 != 0;
    let frame = &data[1..];
    let l = layout(codec, frame, keyframe);
    assert!(l.tiles(frame.len()), "{codec:?} produced a gap or an overlap");
    // Ranges must be inside the frame and non-decreasing.
    for r in l.clear.iter().chain(l.secret.iter()) {
        assert!(r.start <= r.end && r.end <= frame.len());
    }
});
