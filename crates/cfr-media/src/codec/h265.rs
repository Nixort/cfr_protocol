// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! H.265 / HEVC.
//!
//! Identical container handling to H.264, but the NAL header is two bytes
//! rather than one: it carries `nal_unit_type`, `nuh_layer_id` and
//! `nuh_temporal_id_plus1`. Temporal layer identification is what lets a
//! forwarder thin a stream for a congested receiver, so both bytes must stay
//! readable.

use super::Layout;

pub(super) fn layout(frame: &[u8]) -> Layout {
    super::h264::layout_with_header(frame, 2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn two_byte_nal_header_stays_readable() {
        let f = [0, 0, 0, 1, 0x26, 0x01, 0xAA, 0xBB];
        let l = layout(&f);
        assert_eq!(l.clear, vec![0..6]);
        assert_eq!(l.secret, vec![6..8]);
        assert!(l.tiles(f.len()));
    }

    #[test]
    fn a_unit_shorter_than_its_header_is_all_clear() {
        let f = [0, 0, 1, 0x26];
        let l = layout(&f);
        assert!(l.secret.is_empty());
        assert!(l.tiles(f.len()));
    }
}
