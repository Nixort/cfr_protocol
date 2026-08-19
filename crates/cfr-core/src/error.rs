// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Error type for the CFR core.

use alloc::string::String;

/// Everything that can go wrong while processing an operation.
///
/// The variants are deliberately coarse where a finer distinction would leak
/// information to a remote party, and fine where the distinction is needed to
/// drive recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum Error {
    /// The wire encoding was malformed, non-canonical, or truncated.
    #[cfg_attr(feature = "std", error("malformed or non-canonical encoding: {0}"))]
    Encoding(&'static str),

    /// A signature did not verify, or the author is not a known identity.
    #[cfg_attr(feature = "std", error("signature verification failed"))]
    BadSignature,

    /// The author of the operation was not a member in the operation's own
    /// causal past.
    #[cfg_attr(
        feature = "std",
        error("author was not a member at this point in history")
    )]
    NotAMember,

    /// The operation is not authorised by the conference policy.
    #[cfg_attr(feature = "std", error("operation not permitted by policy: {0}"))]
    Unauthorised(&'static str),

    /// The operation depends on operations that have not arrived yet. The
    /// operation has been buffered and will be retried; this is not a failure.
    #[cfg_attr(feature = "std", error("waiting for causal dependencies"))]
    Buffered,

    /// A required node key is missing, so the group key for this version cannot
    /// be computed until repair completes.
    #[cfg_attr(feature = "std", error("missing node keys; repair required"))]
    MissingNodeKeys,

    /// No usable prekey is published for a peer, so no channel can be opened.
    #[cfg_attr(feature = "std", error("no prekey published for peer"))]
    NoPrekey,

    /// AEAD authentication failed while opening a contribution slice or a
    /// repair response.
    #[cfg_attr(feature = "std", error("decryption failed"))]
    Decrypt,

    /// The committed contribution identifier did not match the delivered
    /// secret: the sender equivocated.
    #[cfg_attr(
        feature = "std",
        error("contribution identifier mismatch: sender equivocated")
    )]
    Equivocation,

    /// The local participant is not in the conference, or has been removed.
    #[cfg_attr(feature = "std", error("not a participant"))]
    NotParticipating,

    /// A hard resource limit was exceeded. Present so that a hostile peer
    /// cannot drive unbounded allocation (obligation O13).
    #[cfg_attr(feature = "std", error("resource limit exceeded: {0}"))]
    LimitExceeded(&'static str),

    /// The underlying primitive layer failed.
    #[cfg_attr(feature = "std", error("primitive failure: {0}"))]
    Crypto(cfr_crypto::CryptoError),

    /// An invariant of the local state was violated. This is a bug, not a
    /// hostile input; it is a variant rather than a panic so a conferencing
    /// application can drop one session instead of the whole process.
    #[cfg_attr(feature = "std", error("internal invariant violated: {0}"))]
    Internal(String),
}

impl From<cfr_crypto::CryptoError> for Error {
    fn from(e: cfr_crypto::CryptoError) -> Self {
        Self::Crypto(e)
    }
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Convenience alias.
pub type Result<T> = core::result::Result<T, Error>;
