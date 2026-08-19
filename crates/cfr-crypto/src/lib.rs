// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! CFR cryptographic primitives and wrappers.
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::must_use_candidate, clippy::missing_errors_doc)]

extern crate alloc;

mod aead;
mod dh;
mod hash;
#[cfg(feature = "pq")]
mod kem;
mod secret;
mod sig;

pub use aead::{
    aead_open, aead_open_detached, aead_open_detached_short, aead_seal, aead_seal_detached,
    aead_seal_detached_short, TAG_LEN, TAG_LEN_SHORT,
};
pub use dh::{DhPublic, DhSecret, DH_PUBLIC_LEN};
pub use hash::{hash, hash_into, kdf, kdf_into, mac, mac_verify, nonce, Hasher, MAC_LEN};
#[cfg(feature = "pq")]
pub use kem::{HybridCiphertext, HybridPublic, HybridSecret, HYBRID_CT_LEN, HYBRID_PK_LEN};
pub use secret::{ct_eq, Secret};
pub use sig::{SigPublic, SigSecret, Signature, SIG_LEN, SIG_PUBLIC_LEN};

/// Width of every symmetric key, hash output and node key in CFR.
pub const KEY_LEN: usize = 32;

/// Width of the AEGIS-256 nonce.
pub const NONCE_LEN: usize = 32;

/// A 256-bit symmetric key with guaranteed erasure on drop.
pub type Key = Secret<KEY_LEN>;

/// Errors produced by the primitive layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum CryptoError {
    /// AEAD authentication failed: ciphertext, associated data, key or nonce
    /// did not match.
    #[cfg_attr(feature = "std", error("AEAD authentication failed"))]
    BadTag,
    /// A signature did not verify against the claimed public key.
    #[cfg_attr(feature = "std", error("signature verification failed"))]
    BadSignature,
    /// An encoded public key, secret key or ciphertext had the wrong length or
    /// an invalid encoding.
    #[cfg_attr(feature = "std", error("malformed key material"))]
    BadEncoding,
    /// A ciphertext was shorter than the authentication tag.
    #[cfg_attr(feature = "std", error("ciphertext shorter than authentication tag"))]
    Truncated,
    /// The operating system entropy source failed.
    #[cfg_attr(feature = "std", error("entropy source unavailable"))]
    NoEntropy,
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::BadTag => "AEAD authentication failed",
            Self::BadSignature => "signature verification failed",
            Self::BadEncoding => "malformed key material",
            Self::Truncated => "ciphertext shorter than authentication tag",
            Self::NoEntropy => "entropy source unavailable",
        })
    }
}

/// Fills `out` with cryptographically secure random bytes from the operating
/// system.
///
/// This is the single entropy entry point of the whole library (obligation
/// O10). Nothing else in CFR may call a random number generator directly.
pub fn fill_random(out: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(out).map_err(|_| CryptoError::NoEntropy)
}

/// Returns a fresh random 256-bit secret.
pub fn random_secret() -> Result<Secret<KEY_LEN>, CryptoError> {
    let mut buf = [0u8; KEY_LEN];
    fill_random(&mut buf)?;
    Ok(Secret::from(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_prefixing_prevents_field_ambiguity() {
        // Without length prefixes these two would hash identically. This test
        // is the primitive-layer half of assumption A5.
        assert_ne!(
            hash(b"ctx", &[b"ab".as_slice(), b"c".as_slice()]),
            hash(b"ctx", &[b"a".as_slice(), b"bc".as_slice()])
        );
    }

    #[test]
    fn label_separates_domains() {
        assert_ne!(
            hash(b"one", &[b"x".as_slice()]),
            hash(b"two", &[b"x".as_slice()])
        );
        let k = Secret::from([7u8; 32]);
        assert_ne!(kdf(&k, b"one", &[]), kdf(&k, b"two", &[]));
    }

    #[test]
    fn random_secrets_differ() {
        let a = random_secret().unwrap();
        let b = random_secret().unwrap();
        assert!(!ct_eq(a.as_bytes(), b.as_bytes()));
    }
}
