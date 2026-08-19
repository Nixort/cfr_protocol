// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! AV1 open bitstream units.
//!
//! A temporal unit is a sequence of OBUs. Each begins with a one byte header
//! (`obu_type`, plus flags), an optional one byte extension holding the
//! temporal and spatial identifiers, and an optional LEB128 payload size.
//!
//! Headers and size fields stay readable. `obu_type` distinguishes a sequence
//! header from a frame; the extension carries the layer identifiers a forwarder
//! needs for scalable streams. The payload is content.

use super::Layout;
use alloc::vec::Vec;
use core::ops::Range;

const OBU_EXTENSION_FLAG: u8 = 0b0000_0100;
const OBU_HAS_SIZE_FIELD: u8 = 0b0000_0010;
const OBU_FORBIDDEN_BIT: u8 = 0b1000_0000;

/// Reads an unsigned LEB128 value, returning it and its encoded width.
fn leb128(buf: &[u8], at: usize) -> Option<(usize, usize)> {
    let mut value: u64 = 0;
    let mut i = 0usize;
    while i < 8 {
        let b = *buf.get(at + i)?;
        value |= u64::from(b & 0x7F) << (i * 7);
        i += 1;
        if b & 0x80 == 0 {
            return Some((usize::try_from(value).ok()?, i));
        }
    }
    None
}

pub(super) fn layout(frame: &[u8]) -> Layout {
    let mut units: Vec<(Range<usize>, Range<usize>)> = Vec::new();
    let mut pos = 0usize;

    while pos < frame.len() {
        let header = frame[pos];
        if header & OBU_FORBIDDEN_BIT != 0 {
            return Layout::prefix(0, frame.len());
        }
        let mut meta = 1usize;
        if header & OBU_EXTENSION_FLAG != 0 {
            meta += 1;
        }
        if pos + meta > frame.len() {
            return Layout::prefix(0, frame.len());
        }
        let payload_len = if header & OBU_HAS_SIZE_FIELD != 0 {
            let Some((len, width)) = leb128(frame, pos + meta) else {
                return Layout::prefix(0, frame.len());
            };
            meta += width;
            len
        } else {
            // Without a size field the OBU runs to the end of the temporal
            // unit, which is only well defined for the last one.
            frame.len().saturating_sub(pos + meta)
        };
        let body_start = pos + meta;
        let Some(body_end) = body_start.checked_add(payload_len) else {
            return Layout::prefix(0, frame.len());
        };
        if body_end > frame.len() {
            return Layout::prefix(0, frame.len());
        }
        units.push((pos..body_start, body_start..body_end));
        pos = body_end;
    }

    if units.is_empty() {
        return Layout::prefix(0, frame.len());
    }
    super::h264::from_units(&units, 0, frame.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn single_obu_with_size_field() {
        // header 0x12: type 2 (temporal delimiter is 2), has_size_field set
        let f = [0x12, 0x03, 0xAA, 0xBB, 0xCC];
        let l = layout(&f);
        assert_eq!(l.clear, vec![0..2], "header and size field stay readable");
        assert_eq!(l.secret, vec![2..5]);
        assert!(l.tiles(f.len()));
    }

    #[test]
    fn two_obus_in_one_temporal_unit() {
        let f = [0x12, 0x02, 0x11, 0x22, 0x32, 0x01, 0x33];
        let l = layout(&f);
        assert!(l.tiles(f.len()));
        assert_eq!(l.secret, vec![2..4, 6..7]);
    }

    #[test]
    fn extension_byte_is_readable() {
        // header with extension flag and size field
        let f = [0x16, 0x0A, 0x02, 0xAA, 0xBB];
        let l = layout(&f);
        assert_eq!(
            l.clear,
            vec![0..3],
            "header, extension and size stay readable"
        );
        assert_eq!(l.secret, vec![3..5]);
    }

    #[test]
    fn obu_without_size_field_runs_to_the_end() {
        let f = [0x10, 0xAA, 0xBB, 0xCC];
        let l = layout(&f);
        assert_eq!(l.clear, vec![0..1]);
        assert_eq!(l.secret, vec![1..4]);
    }

    #[test]
    fn forbidden_bit_forces_full_protection() {
        let f = [0x92, 0x01, 0xAA];
        let l = layout(&f);
        assert!(l.clear.is_empty());
        assert!(l.tiles(f.len()));
    }

    #[test]
    fn size_running_past_the_buffer_forces_full_protection() {
        let f = [0x12, 0x40, 0xAA];
        let l = layout(&f);
        assert!(l.clear.is_empty());
        assert!(l.tiles(f.len()));
    }

    #[test]
    fn unterminated_leb128_is_rejected() {
        let f = [0x12, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80];
        let l = layout(&f);
        assert!(l.clear.is_empty());
        assert!(l.tiles(f.len()));
    }
}
