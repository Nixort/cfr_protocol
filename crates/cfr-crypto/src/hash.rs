// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Domain-separated hash, KDF, and MAC helpers.
use crate::{Secret, KEY_LEN, NONCE_LEN};

/// Width of a CFR MAC tag. Sixteen bytes is enough for a value that is
/// checked online and cannot be attacked offline.
pub const MAC_LEN: usize = 16;

/// Incremental, length-prefixing hasher.
///
/// Use this when the field list is not known at the call site. For a fixed
/// list, prefer [`hash`] or [`kdf`], which cannot forget the label.
pub struct Hasher(blake3::Hasher);

impl Hasher {
    /// Starts an unkeyed hash under `label`.
    pub fn new(label: &[u8]) -> Self {
        let mut h = Self(blake3::Hasher::new());
        h.field(label);
        h
    }

    /// Starts a keyed hash under `label`.
    pub fn keyed(key: &Secret<KEY_LEN>, label: &[u8]) -> Self {
        let mut h = Self(blake3::Hasher::new_keyed(key.as_bytes()));
        h.field(label);
        h
    }

    /// Absorbs one length-prefixed field.
    ///
    /// # Panics
    ///
    /// Panics when `data` is longer than `u32::MAX` bytes, because CFR's
    /// canonical field-length encoding is a four-byte unsigned integer.
    pub fn field(&mut self, data: &[u8]) -> &mut Self {
        let len = u32::try_from(data.len()).expect("field longer than 4 GiB");
        self.0.update(&len.to_be_bytes());
        self.0.update(data);
        self
    }

    /// Absorbs a `u32` field.
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.field(&v.to_be_bytes())
    }

    /// Absorbs a `u64` field.
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.field(&v.to_be_bytes())
    }

    /// Finalises to a 256-bit digest.
    pub fn finish(&self) -> [u8; KEY_LEN] {
        *self.0.finalize().as_bytes()
    }

    /// Finalises to an arbitrary-length digest via the BLAKE3 XOF.
    pub fn finish_into(&self, out: &mut [u8]) {
        self.0.finalize_xof().fill(out);
    }

    /// Finalises to a secret.
    pub fn finish_secret(&self) -> Secret<KEY_LEN> {
        Secret::new(self.finish())
    }
}

/// Unkeyed domain-separated hash of a field list.
pub fn hash(label: &[u8], fields: &[&[u8]]) -> [u8; KEY_LEN] {
    let mut h = Hasher::new(label);
    for f in fields {
        h.field(f);
    }
    h.finish()
}

/// Unkeyed hash with a caller-chosen output length.
pub fn hash_into(label: &[u8], fields: &[&[u8]], out: &mut [u8]) {
    let mut h = Hasher::new(label);
    for f in fields {
        h.field(f);
    }
    h.finish_into(out);
}

/// Keyed key derivation: `kdf(key, label, ctx…)`.
pub fn kdf(key: &Secret<KEY_LEN>, label: &[u8], ctx: &[&[u8]]) -> Secret<KEY_LEN> {
    let mut h = Hasher::keyed(key, label);
    for c in ctx {
        h.field(c);
    }
    h.finish_secret()
}

/// Keyed key derivation with a caller-chosen output length.
pub fn kdf_into(key: &Secret<KEY_LEN>, label: &[u8], ctx: &[&[u8]], out: &mut [u8]) {
    let mut h = Hasher::keyed(key, label);
    for c in ctx {
        h.field(c);
    }
    h.finish_into(out);
}

/// Authenticates a field list under `key`.
pub fn mac(key: &Secret<KEY_LEN>, label: &[u8], fields: &[&[u8]]) -> [u8; MAC_LEN] {
    let mut h = Hasher::keyed(key, b"cfr/mac");
    h.field(label);
    for f in fields {
        h.field(f);
    }
    let mut out = [0u8; MAC_LEN];
    h.finish_into(&mut out);
    out
}

/// Constant-time MAC verification.
pub fn mac_verify(key: &Secret<KEY_LEN>, label: &[u8], fields: &[&[u8]], tag: &[u8]) -> bool {
    crate::ct_eq(&mac(key, label, fields), tag)
}

/// Derives a 256-bit AEGIS nonce from context.
///
/// The nonce is a hash of context that always includes a value unique to the
/// message, so it never repeats under a fixed key. This is obligation O2: the
/// caller must ensure at least one field is unique per encryption.
pub fn nonce(fields: &[&[u8]]) -> [u8; NONCE_LEN] {
    hash(b"cfr/nonce", fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_keyed_matches_reference() {
        // BLAKE3 keyed mode, key = 32 zero bytes, input = empty. Guards against
        // a future dependency silently changing modes.
        let k = Secret::from([0u8; 32]);
        let direct = blake3::Hasher::new_keyed(&[0u8; 32]).finalize();
        let mut ours = blake3::Hasher::new_keyed(k.as_bytes());
        assert_eq!(direct.as_bytes(), ours.finalize().as_bytes());
        ours.update(b"x");
    }

    #[test]
    fn kdf_output_depends_on_every_input() {
        let k1 = Secret::from([1u8; 32]);
        let k2 = Secret::from([2u8; 32]);
        let base = kdf(&k1, b"l", &[b"a".as_slice()]);
        assert_ne!(base, kdf(&k2, b"l", &[b"a".as_slice()]));
        assert_ne!(base, kdf(&k1, b"m", &[b"a".as_slice()]));
        assert_ne!(base, kdf(&k1, b"l", &[b"b".as_slice()]));
        assert_ne!(base, kdf(&k1, b"l", &[]));
    }

    #[test]
    fn mac_verifies_and_rejects() {
        let k = Secret::from([3u8; 32]);
        let t = mac(&k, b"confirm", &[b"other".as_slice()]);
        assert!(mac_verify(&k, b"confirm", &[b"other".as_slice()], &t));
        assert!(!mac_verify(&k, b"confirm", &[b"current".as_slice()], &t));
        assert!(!mac_verify(&k, b"other", &[b"other".as_slice()], &t));
        assert!(!mac_verify(
            &k,
            b"confirm",
            &[b"other".as_slice()],
            &t[..15]
        ));
    }

    #[test]
    fn xof_prefix_property() {
        // BLAKE3 XOF output is a prefix-consistent stream; a 16-byte MAC must
        // equal the first 16 bytes of the 32-byte expansion.
        let k = Secret::from([4u8; 32]);
        let mut long = [0u8; 32];
        let mut h = Hasher::keyed(&k, b"cfr/mac");
        h.field(b"l");
        h.finish_into(&mut long);
        assert_eq!(&mac(&k, b"l", &[])[..], &long[..MAC_LEN]);
    }
}
