// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! H.264 / AVC.
//!
//! Two container shapes appear in practice: Annex-B, where units are separated
//! by three or four byte start codes, and length-prefixed (AVCC), where each
//! unit is preceded by a four byte big-endian length. Both are recognised.
//!
//! One byte per unit stays readable: the NAL header, carrying
//! `forbidden_zero_bit`, `nal_ref_idc` and `nal_unit_type`. That is what lets a
//! forwarder recognise parameter sets, IDR pictures and non-reference frames it
//! may drop under congestion.

use super::Layout;
use alloc::vec::Vec;
use core::ops::Range;

/// Byte offsets of Annex-B start codes and the length each occupies.
fn start_codes(frame: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 3 <= frame.len() {
        if frame[i] == 0 && frame[i + 1] == 0 {
            if frame[i + 2] == 1 {
                out.push((i, 3));
                i += 3;
                continue;
            }
            if i + 4 <= frame.len() && frame[i + 2] == 0 && frame[i + 3] == 1 {
                out.push((i, 4));
                i += 4;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Splits an Annex-B frame into `(unit_start, unit_end)` pairs, with the start
/// code itself reported separately.
pub(super) fn annex_b_units(frame: &[u8]) -> Option<Vec<(Range<usize>, Range<usize>)>> {
    let codes = start_codes(frame);
    if codes.is_empty() || codes[0].0 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(codes.len());
    for (idx, (pos, len)) in codes.iter().enumerate() {
        let body_start = pos + len;
        let body_end = codes.get(idx + 1).map_or(frame.len(), |(n, _)| *n);
        if body_end < body_start {
            return None;
        }
        out.push((*pos..body_start, body_start..body_end));
    }
    Some(out)
}

/// Splits a length-prefixed frame into `(prefix, body)` pairs.
pub(super) fn length_prefixed_units(frame: &[u8]) -> Option<Vec<(Range<usize>, Range<usize>)>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < frame.len() {
        if i + 4 > frame.len() {
            return None;
        }
        let n = u32::from_be_bytes([frame[i], frame[i + 1], frame[i + 2], frame[i + 3]]) as usize;
        // A zero-length or oversized unit means this is not AVCC after all.
        if n == 0 || i + 4 + n > frame.len() {
            return None;
        }
        out.push((i..i + 4, i + 4..i + 4 + n));
        i += 4 + n;
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Builds a layout keeping `header` bytes of each unit readable.
pub(super) fn from_units(
    units: &[(Range<usize>, Range<usize>)],
    header: usize,
    total: usize,
) -> Layout {
    let mut l = Layout::default();
    for (prefix, body) in units {
        let clear_end = (body.start + header).min(body.end);
        l.clear.push(prefix.start..clear_end);
        if clear_end < body.end {
            l.secret.push(clear_end..body.end);
        }
    }
    // Merge adjacent clear ranges so the layout is minimal and comparable.
    let mut merged: Vec<Range<usize>> = Vec::with_capacity(l.clear.len());
    for r in l.clear {
        match merged.last_mut() {
            Some(prev) if prev.end == r.start => prev.end = r.end,
            _ => merged.push(r),
        }
    }
    l.clear = merged;
    debug_assert!(l.tiles(total));
    l
}

pub(super) fn layout_with_header(frame: &[u8], header: usize) -> Layout {
    if frame.is_empty() {
        return Layout::default();
    }
    if let Some(units) = annex_b_units(frame) {
        return from_units(&units, header, frame.len());
    }
    if let Some(units) = length_prefixed_units(frame) {
        return from_units(&units, header, frame.len());
    }
    // Unrecognised container: protect everything.
    Layout::prefix(0, frame.len())
}

pub(super) fn layout(frame: &[u8]) -> Layout {
    layout_with_header(frame, 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn annex_b_three_byte_start_code() {
        // start code, NAL header 0x65 (IDR), then payload
        let f = [0, 0, 1, 0x65, 0xAA, 0xBB, 0xCC];
        let l = layout(&f);
        assert_eq!(
            l.clear,
            vec![0..4],
            "start code and NAL header stay readable"
        );
        assert_eq!(l.secret, vec![4..7]);
        assert!(l.tiles(f.len()));
    }

    #[test]
    fn annex_b_multiple_units() {
        let f = [
            0, 0, 0, 1, 0x67, 0x11, 0x22, // SPS
            0, 0, 0, 1, 0x68, 0x33, // PPS
            0, 0, 1, 0x65, 0x44, 0x55, // IDR
        ];
        let l = layout(&f);
        assert!(l.tiles(f.len()));
        assert_eq!(l.secret, vec![5..7, 12..13, 17..19]);
        // Every NAL header byte must be readable to a forwarder.
        for off in [4usize, 11, 16] {
            assert!(
                l.clear.iter().any(|r| r.contains(&off)),
                "NAL header at {off} must be readable"
            );
        }
    }

    #[test]
    fn length_prefixed_container() {
        let f = [0, 0, 0, 3, 0x65, 0xAA, 0xBB, 0, 0, 0, 2, 0x41, 0xCC];
        let l = layout(&f);
        assert!(l.tiles(f.len()));
        assert_eq!(l.secret, vec![5..7, 12..13]);
    }

    #[test]
    fn unrecognised_input_is_fully_protected() {
        let f = [0xAA, 0xBB, 0xCC, 0xDD];
        let l = layout(&f);
        assert!(l.clear.is_empty());
        assert_eq!(l.secret, vec![0..4]);
    }

    #[test]
    fn truncated_length_prefix_falls_back_to_full_protection() {
        let f = [0, 0, 0, 9, 0x65];
        let l = layout(&f);
        assert!(l.clear.is_empty());
        assert!(l.tiles(f.len()));
    }

    #[test]
    fn empty_unit_bodies_do_not_break_tiling() {
        let f = [0, 0, 1, 0, 0, 1, 0x65, 0xAA];
        let l = layout(&f);
        assert!(l.tiles(f.len()));
    }
}
