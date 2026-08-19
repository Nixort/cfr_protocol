// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! VP8 and VP9.
//!
//! # VP8
//!
//! A VP8 frame opens with a three byte uncompressed data chunk holding the
//! frame type, version, `show_frame` and the size of the first partition. A key
//! frame adds a three byte start code and four bytes of dimensions, seven more
//! in total. Those bytes are what a forwarder reads to recognise a key frame,
//! so they stay readable; the compressed partitions do not.
//!
//! # VP9
//!
//! VP9's uncompressed header is bit packed and its length depends on fields
//! inside it, so there is no fixed prefix that can be exposed without a full
//! parse. Rather than parse a bit stream to decide what to reveal — where an
//! error would leak picture data — the whole frame is protected. Scalability
//! metadata that a forwarder needs travels in the RTP payload descriptor, which
//! is outside the encrypted frame, so nothing is lost.

use super::Layout;

const VP8_UNCOMPRESSED: usize = 3;
const VP8_KEYFRAME_EXTRA: usize = 7;

pub(super) fn vp8_layout(frame: &[u8], keyframe: bool) -> Layout {
    // Trust the bitstream over the caller's flag when they disagree: bit 0 of
    // the first byte is `frame_type`, zero for a key frame.
    let declared_key = frame.first().is_some_and(|b| b & 0x01 == 0);
    let is_key = keyframe && declared_key;
    let n = if is_key {
        VP8_UNCOMPRESSED + VP8_KEYFRAME_EXTRA
    } else {
        VP8_UNCOMPRESSED
    };
    Layout::prefix(n, frame.len())
}

pub(super) fn vp9_layout(frame: &[u8]) -> Layout {
    Layout::prefix(0, frame.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn vp8_delta_frame_exposes_three_bytes() {
        let f = [0x31, 0x00, 0x00, 1, 2, 3, 4];
        let l = vp8_layout(&f, false);
        assert_eq!(l.clear, vec![0..3]);
        assert_eq!(l.secret, vec![3..7]);
    }

    #[test]
    fn vp8_key_frame_exposes_ten_bytes() {
        let mut f = alloc::vec![0u8; 20];
        f[0] = 0x10; // frame_type = 0 -> key frame
        f[3] = 0x9d;
        f[4] = 0x01;
        f[5] = 0x2a;
        let l = vp8_layout(&f, true);
        assert_eq!(l.clear, vec![0..10]);
        assert_eq!(l.secret, vec![10..20]);
    }

    #[test]
    fn vp8_ignores_a_false_key_frame_claim() {
        // Caller says key frame, bitstream says delta. Revealing ten bytes on a
        // delta frame would expose compressed data, so the bitstream wins.
        let f = [0x31, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let l = vp8_layout(&f, true);
        assert_eq!(l.clear, vec![0..3]);
    }

    #[test]
    fn vp8_short_frame_does_not_overrun() {
        let f = [0x10, 0x00];
        let l = vp8_layout(&f, true);
        assert!(l.tiles(f.len()));
        assert_eq!(l.clear, vec![0..2]);
    }

    #[test]
    fn vp9_is_fully_protected() {
        let f = [0x82, 0x49, 0x83, 0x42];
        let l = vp9_layout(&f);
        assert!(l.clear.is_empty());
        assert_eq!(l.secret, vec![0..4]);
    }
}
