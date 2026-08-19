// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Optional hybrid key-encapsulation support.
use crate::{CryptoError, DhPublic, DhSecret, Hasher, Secret, KEY_LEN};
use alloc::vec::Vec;
use ml_kem::kem::{Decapsulate, Key, KeyExport};
use ml_kem::ml_kem_768::{DecapsulationKey as InnerDk, EncapsulationKey as InnerEk};

type Inner = ml_kem::MlKem768;

const MLKEM_PK_LEN: usize = 1184;
const MLKEM_CT_LEN: usize = 1088;

/// Width of an encoded hybrid public key.
pub const HYBRID_PK_LEN: usize = 32 + MLKEM_PK_LEN;
/// Width of an encoded hybrid ciphertext.
pub const HYBRID_CT_LEN: usize = 32 + MLKEM_CT_LEN;

/// A hybrid decapsulation key.
pub struct HybridSecret {
    x: DhSecret,
    pq: InnerDk,
}

/// A hybrid encapsulation key.
#[derive(Clone)]
pub struct HybridPublic {
    x: DhPublic,
    pq: InnerEk,
}

/// A hybrid ciphertext.
#[derive(Clone, PartialEq, Eq)]
pub struct HybridCiphertext(Vec<u8>);

impl HybridSecret {
    /// Generates a hybrid key pair.
    ///
    /// ML-KEM key generation is seeded from a single 64-byte draw rather than
    /// through an `RngCore` adaptor, so the whole crate keeps exactly one
    /// entropy entry point (obligation O10).
    pub fn generate() -> Result<Self, CryptoError> {
        let mut seed = ml_kem::Seed::default();
        crate::fill_random(seed.as_mut_slice())?;
        let dk = InnerDk::from_seed(seed);
        Ok(Self {
            x: DhSecret::generate()?,
            pq: dk,
        })
    }

    /// The matching encapsulation key.
    pub fn public(&self) -> HybridPublic {
        HybridPublic {
            x: self.x.public(),
            pq: self.pq.encapsulation_key().clone(),
        }
    }

    /// Recovers the shared secret from a ciphertext.
    pub fn decapsulate(&self, ct: &HybridCiphertext) -> Result<Secret<KEY_LEN>, CryptoError> {
        if ct.0.len() != HYBRID_CT_LEN {
            return Err(CryptoError::BadEncoding);
        }
        let (x_ct, pq_ct) = ct.0.split_at(32);
        let x_pub = DhPublic::from_slice(x_ct)?;
        let ss_x = self.x.agree(&x_pub).ok_or(CryptoError::BadEncoding)?;

        let arr = ml_kem::kem::Ciphertext::<Inner>::try_from(pq_ct)
            .map_err(|_| CryptoError::BadEncoding)?;
        // ML-KEM decapsulation is infallible: a malformed ciphertext yields an
        // unrelated shared secret (implicit rejection). The AEAD tag one layer
        // up is what converts that into a visible rejection.
        let ss_pq = self.pq.decapsulate(&arr);

        Ok(combine(&ss_x, ss_pq.as_slice(), &ct.0, &self.public()))
    }
}

impl HybridPublic {
    /// Produces a ciphertext and the shared secret it carries.
    pub fn encapsulate(&self) -> Result<(HybridCiphertext, Secret<KEY_LEN>), CryptoError> {
        let eph = DhSecret::generate()?;
        let ss_x = eph.agree(&self.x).ok_or(CryptoError::BadEncoding)?;

        let mut m = ml_kem::B32::default();
        crate::fill_random(m.as_mut_slice())?;
        let (pq_ct, ss_pq) = self.pq.encapsulate_deterministic(&m);
        m.as_mut_slice().fill(0);

        let mut ct = Vec::with_capacity(HYBRID_CT_LEN);
        ct.extend_from_slice(eph.public().as_bytes());
        ct.extend_from_slice(pq_ct.as_slice());

        let ss = combine(&ss_x, ss_pq.as_slice(), &ct, self);
        Ok((HybridCiphertext(ct), ss))
    }

    /// The encoded form.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_PK_LEN);
        out.extend_from_slice(self.x.as_bytes());
        out.extend_from_slice(self.pq.to_bytes().as_slice());
        out
    }

    /// Parses an encoded hybrid public key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != HYBRID_PK_LEN {
            return Err(CryptoError::BadEncoding);
        }
        let (x, pq) = bytes.split_at(32);
        let enc = Key::<InnerEk>::try_from(pq).map_err(|_| CryptoError::BadEncoding)?;
        Ok(Self {
            x: DhPublic::from_slice(x)?,
            pq: InnerEk::new(&enc).map_err(|_| CryptoError::BadEncoding)?,
        })
    }
}

impl HybridCiphertext {
    /// The encoded form.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Parses an encoded hybrid ciphertext.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != HYBRID_CT_LEN {
            return Err(CryptoError::BadEncoding);
        }
        Ok(Self(bytes.to_vec()))
    }
}

/// The hybrid combiner. Both shared secrets, both ciphertexts and both public
/// keys enter the derivation, so the result is bound to the exact exchange.
fn combine(ss_x: &Secret<KEY_LEN>, ss_pq: &[u8], ct: &[u8], pk: &HybridPublic) -> Secret<KEY_LEN> {
    let mut seed = Hasher::new(b"cfr/hybrid/seed");
    seed.field(ss_x.as_bytes());
    seed.field(ss_pq);
    let root = seed.finish_secret();

    let mut h = Hasher::keyed(&root, b"cfr/hybrid");
    h.field(ct);
    h.field(&pk.to_bytes());
    h.finish_secret()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encapsulation_roundtrips() {
        let sk = HybridSecret::generate().unwrap();
        let pk = sk.public();
        let (ct, ss1) = pk.encapsulate().unwrap();
        let ss2 = sk.decapsulate(&ct).unwrap();
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn public_key_roundtrips() {
        let sk = HybridSecret::generate().unwrap();
        let bytes = sk.public().to_bytes();
        assert_eq!(bytes.len(), HYBRID_PK_LEN);
        let pk = HybridPublic::from_bytes(&bytes).unwrap();
        let (ct, ss1) = pk.encapsulate().unwrap();
        assert_eq!(sk.decapsulate(&ct).unwrap(), ss1);
    }

    #[test]
    fn mutated_ciphertext_changes_secret() {
        let sk = HybridSecret::generate().unwrap();
        let (ct, ss) = sk.public().encapsulate().unwrap();
        let mut bad = ct.as_bytes().to_vec();
        // Flip a bit in the ML-KEM half. ML-KEM is IND-CCA with implicit
        // rejection, so decapsulation still returns a value, but a different
        // one. The AEAD tag downstream is what turns this into a rejection.
        bad[40] ^= 1;
        let bad = HybridCiphertext::from_bytes(&bad).unwrap();
        assert_ne!(sk.decapsulate(&bad).unwrap(), ss);
    }

    #[test]
    fn wrong_length_rejected() {
        assert!(HybridPublic::from_bytes(&[0u8; 10]).is_err());
        assert!(HybridCiphertext::from_bytes(&[0u8; 10]).is_err());
    }
}
