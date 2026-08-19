// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Errors from the media layer.

/// Why a frame could not be protected or opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum Error {
    /// The packet is too short or its trailer is not well formed.
    #[cfg_attr(feature = "std", error("malformed packet"))]
    Malformed,
    /// No group key version is installed.
    #[cfg_attr(feature = "std", error("no group key installed"))]
    NoKey,
    /// The frame names a key version that is not retained. Either the frame is
    /// older than the overlap window, or this participant has not caught up.
    #[cfg_attr(feature = "std", error("unknown key version"))]
    UnknownVersion,
    /// The frame names a sender who is not in the roster of that version.
    #[cfg_attr(feature = "std", error("unknown sender"))]
    UnknownSender,
    /// The frame claims to come from this participant.
    #[cfg_attr(feature = "std", error("frame claims to be our own"))]
    OwnFrame,
    /// The frame was already seen.
    #[cfg_attr(feature = "std", error("replayed frame"))]
    Replay,
    /// The frame belongs to a ratchet epoch already passed.
    #[cfg_attr(feature = "std", error("frame belongs to a retired epoch"))]
    Stale,
    /// Authentication failed.
    #[cfg_attr(feature = "std", error("authentication failed"))]
    BadTag,
    /// The per-sender frame counter would wrap. Rekey instead.
    #[cfg_attr(feature = "std", error("frame counter exhausted"))]
    CounterExhausted,
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Convenience alias.
pub type Result<T> = core::result::Result<T, Error>;
