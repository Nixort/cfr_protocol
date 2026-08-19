// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Codec-aware frame partitioning.
//!
//! A selective forwarding unit routes and drops frames without holding the
//! group key. To keep working, it needs the parts of the bitstream that carry
//! structure — NAL headers, OBU headers, the VP8 uncompressed chunk — while
//! everything that carries picture or sound must be unreadable.
//!
//! Every codec module answers one question: which byte ranges of this frame
//! are structure, and which are content. The answer is a [`Layout`]. Structure
//! stays in the clear but is covered by the authentication tag, so an
//! intermediary can read and route on it and cannot alter it.
//!
//! AEGIS-256 is length preserving, so content bytes are encrypted **in place**.
//! The protected frame has the same internal geometry as the original: start
//! codes are where they were, unit lengths are unchanged, and a parser that
//! walks the frame sees the same units it saw before.

use alloc::vec::Vec;
use core::ops::Range;

mod av1;
mod h264;
mod h265;
mod vpx;

/// Which codec produced a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Codec {
    /// H.264 / AVC, Annex-B or length-prefixed.
    H264,
    /// H.265 / HEVC, Annex-B or length-prefixed.
    H265,
    /// AV1 open bitstream units.
    Av1,
    /// VP8.
    Vp8,
    /// VP9.
    Vp9,
    /// Opus audio.
    Opus,
    /// Anything else: the whole frame is content.
    Generic,
}

impl Codec {
    /// Whether this codec carries audio.
    ///
    /// Audio frames are small and frequent, so they use the 128-bit tag
    /// profile; a 256-bit tag would be a third of a typical Opus packet.
    pub fn is_audio(self) -> bool {
        matches!(self, Self::Opus)
    }
}

/// How a frame splits into routable structure and protected content.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Layout {
    /// Ranges left readable, in ascending order.
    pub clear: Vec<Range<usize>>,
    /// Ranges to encrypt, in ascending order.
    pub secret: Vec<Range<usize>>,
}

impl Layout {
    /// A layout where a fixed prefix stays readable.
    pub fn prefix(len: usize, total: usize) -> Self {
        let cut = len.min(total);
        let mut l = Self::default();
        if cut > 0 {
            l.clear.push(0..cut);
        }
        if cut < total {
            l.secret.push(cut..total);
        }
        l
    }

    /// Total number of protected bytes.
    pub fn secret_len(&self) -> usize {
        self.secret
            .iter()
            .map(core::iter::ExactSizeIterator::len)
            .sum()
    }

    /// Whether the ranges tile `total` exactly, without gaps or overlap.
    ///
    /// Every parser must satisfy this. A gap would silently leave content
    /// readable; an overlap would encrypt bytes twice and corrupt the frame.
    /// The property is asserted in tests for every codec and checked by the
    /// fuzz target on arbitrary input.
    pub fn tiles(&self, total: usize) -> bool {
        let mut all: Vec<&Range<usize>> = self.clear.iter().chain(self.secret.iter()).collect();
        all.sort_by_key(|r| r.start);
        let mut pos = 0usize;
        for r in all {
            if r.start != pos || r.end < r.start || r.end > total {
                return false;
            }
            pos = r.end;
        }
        pos == total
    }
}

/// Computes the layout for `frame`.
///
/// Parsing never fails: a bitstream that does not match the expected shape
/// falls back to protecting everything. Failing closed matters more than
/// preserving routability, because the alternative — guessing a header length
/// on malformed input — could expose content.
pub fn layout(codec: Codec, frame: &[u8], keyframe: bool) -> Layout {
    match codec {
        Codec::H264 => h264::layout(frame),
        Codec::H265 => h265::layout(frame),
        Codec::Av1 => av1::layout(frame),
        Codec::Vp8 => vpx::vp8_layout(frame, keyframe),
        Codec::Vp9 => vpx::vp9_layout(frame),
        // The Opus table-of-contents byte carries frame count, bandwidth and
        // configuration. Jitter buffers read it; the encoded audio does not
        // begin until byte one.
        Codec::Opus => Layout::prefix(1, frame.len()),
        Codec::Generic => Layout::prefix(0, frame.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_codec_tiles_every_input() {
        let samples: [&[u8]; 6] = [
            &[],
            &[0x00],
            &[0x00, 0x00, 0x01, 0x65, 0xAA, 0xBB],
            &[
                0x9d, 0x01, 0x2a, 0x40, 0x01, 0xf0, 0x00, 0x10, 0x20, 0x30, 0x40,
            ],
            &[0xFF; 64],
            &[0x12, 0x00, 0x0A, 0x01, 0x02, 0x03],
        ];
        for c in [
            Codec::H264,
            Codec::H265,
            Codec::Av1,
            Codec::Vp8,
            Codec::Vp9,
            Codec::Opus,
            Codec::Generic,
        ] {
            for s in samples {
                for kf in [false, true] {
                    let l = layout(c, s, kf);
                    assert!(l.tiles(s.len()), "{c:?} failed to tile {s:?}");
                }
            }
        }
    }

    #[test]
    fn opus_exposes_only_the_toc_byte() {
        let l = layout(Codec::Opus, &[0x78, 1, 2, 3], false);
        assert_eq!(l.clear, alloc::vec![0..1]);
        assert_eq!(l.secret, alloc::vec![1..4]);
    }

    #[test]
    fn generic_protects_everything() {
        let l = layout(Codec::Generic, &[1, 2, 3], false);
        assert!(l.clear.is_empty());
        assert_eq!(l.secret_len(), 3);
    }
}
