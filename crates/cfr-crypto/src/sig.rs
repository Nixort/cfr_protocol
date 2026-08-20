// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Ed25519 signing helpers.
use crate::CryptoError;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

/// Width of an encoded Ed25519 signature.
pub const SIG_LEN: usize = 64;
/// Width of an encoded Ed25519 public key.
pub const SIG_PUBLIC_LEN: usize = 32;

/// An Ed25519 signing key. Zeroized on drop by `ed25519-dalek`.
pub struct SigSecret(SigningKey);

/// An Ed25519 verifying key. This is a participant's long-term identity in
/// CFR.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SigPublic([u8; SIG_PUBLIC_LEN]);

/// A detached Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; SIG_LEN]);

impl SigSecret {
    /// Generates a fresh identity key pair.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut seed = [0u8; 32];
        crate::fill_random(&mut seed)?;
        let sk = SigningKey::from_bytes(&seed);
        seed.fill(0);
        Ok(Self(sk))
    }

    /// Reconstructs a signing key from a seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// Returns the seed for the internal persistence codec.
    ///
    /// This deliberately secret-bearing hook is available only when the
    /// application persistence feature is enabled.
    #[cfg(feature = "persistence")]
    #[doc(hidden)]
    pub fn persistence_seed(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// The matching identity public key.
    pub fn public(&self) -> SigPublic {
        SigPublic(self.0.verifying_key().to_bytes())
    }

    /// Signs a message.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature(self.0.sign(msg).to_bytes())
    }
}

impl core::fmt::Debug for SigSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SigSecret(redacted)")
    }
}

impl SigPublic {
    /// Parses an identity key from bytes.
    pub fn from_bytes(bytes: [u8; SIG_PUBLIC_LEN]) -> Self {
        Self(bytes)
    }

    /// Parses an identity key from a slice, rejecting the wrong length.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| CryptoError::BadEncoding)
    }

    /// The encoded form.
    pub fn as_bytes(&self) -> &[u8; SIG_PUBLIC_LEN] {
        &self.0
    }

    /// Verifies a signature, rejecting small-order and mixed-order forms.
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), CryptoError> {
        let vk = VerifyingKey::from_bytes(&self.0).map_err(|_| CryptoError::BadEncoding)?;
        let s = ed25519_dalek::Signature::from_bytes(&sig.0);
        vk.verify_strict(msg, &s)
            .map_err(|_| CryptoError::BadSignature)
    }
}

impl core::fmt::Debug for SigPublic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Eight hex characters is enough to identify a participant in a log
        // without pasting the whole key into every line.
        for b in &self.0[..4] {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl Signature {
    /// Parses a signature from bytes.
    pub fn from_bytes(bytes: [u8; SIG_LEN]) -> Self {
        Self(bytes)
    }

    /// Parses a signature from a slice, rejecting the wrong length.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| CryptoError::BadEncoding)
    }

    /// The encoded form.
    pub fn as_bytes(&self) -> &[u8; SIG_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Signature(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let sk = SigSecret::generate().unwrap();
        let pk = sk.public();
        let sig = sk.sign(b"message");
        assert!(pk.verify(b"message", &sig).is_ok());
        assert!(pk.verify(b"other", &sig).is_err());
    }

    #[test]
    fn wrong_key_rejects() {
        let a = SigSecret::generate().unwrap();
        let b = SigSecret::generate().unwrap();
        let sig = a.sign(b"m");
        assert!(b.public().verify(b"m", &sig).is_err());
    }

    #[test]
    fn mutated_signature_rejects() {
        let sk = SigSecret::generate().unwrap();
        let sig = sk.sign(b"m");
        for i in [0usize, 31, 63] {
            let mut bytes = *sig.as_bytes();
            bytes[i] ^= 1;
            assert!(sk
                .public()
                .verify(b"m", &Signature::from_bytes(bytes))
                .is_err());
        }
    }

    #[test]
    fn small_order_key_rejects() {
        // The canonical small-order point of order 8; verify_strict must
        // refuse it regardless of the signature.
        let pk = SigPublic::from_bytes([0u8; 32]);
        assert!(pk.verify(b"m", &Signature::from_bytes([0u8; 64])).is_err());
    }

    #[test]
    fn deterministic_from_seed() {
        let a = SigSecret::from_seed(&[5u8; 32]);
        let b = SigSecret::from_seed(&[5u8; 32]);
        assert_eq!(a.public(), b.public());
        assert_eq!(a.sign(b"m").as_bytes(), b.sign(b"m").as_bytes());
    }
}
