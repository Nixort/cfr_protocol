// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! X25519 key agreement.

use crate::{CryptoError, Secret, KEY_LEN};
use x25519_dalek::{PublicKey, StaticSecret};

/// Width of an encoded X25519 public key.
pub const DH_PUBLIC_LEN: usize = 32;

/// An X25519 private key. Zeroized on drop by `x25519-dalek`.
pub struct DhSecret(StaticSecret);

/// An X25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DhPublic([u8; DH_PUBLIC_LEN]);

impl DhSecret {
    /// Generates a fresh key pair from the system entropy source.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut seed = [0u8; 32];
        crate::fill_random(&mut seed)?;
        let sk = StaticSecret::from(seed);
        seed.fill(0);
        Ok(Self(sk))
    }

    /// Reconstructs a private key from raw bytes. Used only by tests and by
    /// deterministic replay of a fuzzing seed.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(StaticSecret::from(bytes))
    }

    /// The matching public key.
    pub fn public(&self) -> DhPublic {
        DhPublic(PublicKey::from(&self.0).to_bytes())
    }

    /// Computes the shared secret with `peer`.
    ///
    /// Returns `None` when the result is the all-zero point, which happens for
    /// low-order peer keys. Rejecting it here means no caller can derive a key
    /// from a contributory-behaviour failure.
    pub fn agree(&self, peer: &DhPublic) -> Option<Secret<KEY_LEN>> {
        let shared = self.0.diffie_hellman(&PublicKey::from(peer.0));
        if !shared.was_contributory() {
            return None;
        }
        Some(Secret::new(shared.to_bytes()))
    }
}

impl core::fmt::Debug for DhSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DhSecret(redacted)")
    }
}

impl DhPublic {
    /// Parses a public key from bytes.
    pub fn from_bytes(bytes: [u8; DH_PUBLIC_LEN]) -> Self {
        Self(bytes)
    }

    /// Parses a public key from a slice, rejecting the wrong length.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| CryptoError::BadEncoding)
    }

    /// The encoded form.
    pub fn as_bytes(&self) -> &[u8; DH_PUBLIC_LEN] {
        &self.0
    }
}

impl PartialOrd for DhPublic {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DhPublic {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agreement_is_symmetric() {
        let a = DhSecret::generate().unwrap();
        let b = DhSecret::generate().unwrap();
        let ab = a.agree(&b.public()).unwrap();
        let ba = b.agree(&a.public()).unwrap();
        assert_eq!(ab, ba);
    }

    #[test]
    fn distinct_pairs_give_distinct_secrets() {
        let a = DhSecret::generate().unwrap();
        let b = DhSecret::generate().unwrap();
        let c = DhSecret::generate().unwrap();
        assert_ne!(a.agree(&b.public()).unwrap(), a.agree(&c.public()).unwrap());
    }

    #[test]
    fn low_order_points_are_rejected() {
        let a = DhSecret::generate().unwrap();
        // The all-zero u-coordinate and the order-8 points from RFC 7748 §6.1
        // security considerations all produce a zero shared secret.
        for p in [[0u8; 32], {
            let mut p = [0u8; 32];
            p[0] = 1;
            p
        }] {
            assert!(a.agree(&DhPublic::from_bytes(p)).is_none());
        }
    }

    #[test]
    fn public_key_encoding_roundtrips() {
        let a = DhSecret::generate().unwrap();
        let pk = a.public();
        assert_eq!(DhPublic::from_slice(pk.as_bytes()).unwrap(), pk);
        assert!(DhPublic::from_slice(&pk.as_bytes()[..31]).is_err());
    }
}
