// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Erasable secret buffers (obligation O1) and constant-time comparison
//! (obligation O11).

use core::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A fixed-width secret that is zeroized when dropped.
///
/// `Secret` deliberately does **not** implement `Copy`, `Display`, or a
/// value-revealing `Debug`. Every path that needs the bytes must call
/// [`Secret::as_bytes`] explicitly, which makes the places where secret
/// material escapes greppable.
///
/// Erasure is best-effort at the language level: it guarantees the *object* is
/// cleared, not that no copy was left behind by an optimiser, an allocator or
/// the kernel. Assumption A6 of the security analysis is a statement about the
/// whole system, not about this type alone.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret<const N: usize>([u8; N]);

impl<const N: usize> Secret<N> {
    /// Wraps raw bytes as a secret.
    pub const fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// An all-zero secret. Used as the identity element of the node-key XOR
    /// accumulator, never as a key.
    pub const fn zero() -> Self {
        Self([0u8; N])
    }

    /// Borrows the secret bytes.
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    /// Mutably borrows the secret bytes.
    pub fn as_mut_bytes(&mut self) -> &mut [u8; N] {
        &mut self.0
    }

    /// Parses a secret from a slice, rejecting the wrong length.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let arr: [u8; N] = bytes.try_into().ok()?;
        Some(Self(arr))
    }

    /// XORs `other` into `self` in place. This is the node-key accumulator of
    /// the group key derivation.
    pub fn xor_in_place(&mut self, other: &Self) {
        for (a, b) in self.0.iter_mut().zip(other.0.iter()) {
            *a ^= *b;
        }
    }

    /// Constant-time equality.
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }

    /// Overwrites the secret immediately rather than waiting for drop.
    ///
    /// Call this at the exact point the protocol declares a value destroyed;
    /// relying on drop order alone makes the forward-secrecy horizon depend on
    /// the compiler.
    pub fn wipe(&mut self) {
        self.0.zeroize();
    }
}

impl<const N: usize> From<[u8; N]> for Secret<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self(bytes)
    }
}

impl<const N: usize> fmt::Debug for Secret<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret<{N}>(redacted)")
    }
}

impl<const N: usize> PartialEq for Secret<N> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other)
    }
}

impl<const N: usize> Eq for Secret<N> {}

/// Constant-time slice comparison. Returns `false` for length mismatch without
/// leaking which byte differed.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_is_involutive() {
        let mut a = Secret::from([0xAAu8; 32]);
        let b = Secret::from([0x55u8; 32]);
        a.xor_in_place(&b);
        assert_eq!(a.as_bytes(), &[0xFFu8; 32]);
        a.xor_in_place(&b);
        assert_eq!(a.as_bytes(), &[0xAAu8; 32]);
    }

    #[test]
    fn debug_does_not_reveal() {
        let s = Secret::from([0x42u8; 32]);
        assert!(!format!("{s:?}").contains("42"));
    }

    #[test]
    fn wipe_clears() {
        let mut s = Secret::from([9u8; 32]);
        s.wipe();
        assert_eq!(s.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn ct_eq_rejects_length_mismatch() {
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(ct_eq(b"abc", b"abc"));
    }
}
