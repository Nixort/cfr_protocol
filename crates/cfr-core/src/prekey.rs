// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! One-time prekey management.
use alloc::collections::BTreeSet;
use cfr_crypto::{CryptoError, DhPublic, DhSecret, Secret, SigPublic, KEY_LEN};

/// Backstop deadline, in local ticks, after which a generation's private half
/// is destroyed whether or not every channel was opened.
pub const SEAL_AFTER: u32 = 64;

/// A single prekey generation.
pub struct PrekeyPool {
    pub(crate) generation: u32,
    pub(crate) secret: Option<DhSecret>,
    pub(crate) public: DhPublic,
    pub(crate) established: BTreeSet<SigPublic>,
    pub(crate) age: u32,
}

impl PrekeyPool {
    /// Creates generation zero.
    pub fn new() -> Result<Self, CryptoError> {
        Self::at(0)
    }

    /// Creates a specific generation.
    pub fn at(generation: u32) -> Result<Self, CryptoError> {
        let secret = DhSecret::generate()?;
        let public = secret.public();
        Ok(Self {
            generation,
            secret: Some(secret),
            public,
            established: BTreeSet::new(),
            age: 0,
        })
    }

    /// The generation counter.
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// The published public half.
    pub fn public(&self) -> DhPublic {
        self.public
    }

    /// Whether the private half has been destroyed.
    pub fn is_sealed(&self) -> bool {
        self.secret.is_none()
    }

    /// Advances the deadline clock, destroying the secret when it expires.
    pub fn tick(&mut self) {
        self.age = self.age.saturating_add(1);
        if self.age >= SEAL_AFTER {
            self.seal();
        }
    }

    /// Destroys the private half immediately.
    pub fn seal(&mut self) {
        self.secret = None;
    }

    /// Opens a channel for `peer`, sealing once every identity in `expected`
    /// has been served.
    ///
    /// Sealing is driven by the **set** of peers served, not by a count. A
    /// count is wrong as soon as the roster grows: the generation would be
    /// destroyed while a member admitted a moment later still needs it, and
    /// that member would be permanently unable to open a channel.
    ///
    /// Returns `None` once sealed. A caller that gets `None` cannot use this
    /// generation and must wait for a fresher one; that is the designed
    /// behaviour of forward secrecy, not a failure.
    pub fn agree_for(
        &mut self,
        peer: &SigPublic,
        eph: &DhPublic,
        expected: &BTreeSet<SigPublic>,
    ) -> Option<Secret<KEY_LEN>> {
        let sk = self.secret.as_ref()?;
        let shared = sk.agree(eph)?;
        self.established.insert(*peer);
        if !expected.is_empty() && expected.iter().all(|p| self.established.contains(p)) {
            self.seal();
        }
        Some(shared)
    }

    /// Agrees for a one-shot sealed envelope without counting towards sealing.
    ///
    /// Envelopes carry welcomes and repair responses. They are not channels, so
    /// serving one must not bring the destruction of the generation forward.
    pub fn agree_envelope(&mut self, eph: &DhPublic) -> Option<Secret<KEY_LEN>> {
        self.secret.as_ref()?.agree(eph)
    }

    /// Replaces this pool with a fresh generation and destroys the old secret.
    pub fn rotate(&mut self) -> Result<(), CryptoError> {
        let next = Self::at(self.generation.wrapping_add(1))?;
        self.seal();
        *self = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> SigPublic {
        SigPublic::from_bytes([n; 32])
    }

    #[test]
    fn seals_once_every_expected_peer_is_served() {
        let mut p = PrekeyPool::new().unwrap();
        let eph = DhSecret::generate().unwrap();
        let expect: BTreeSet<SigPublic> = [id(1), id(2)].into_iter().collect();
        assert!(p.agree_for(&id(1), &eph.public(), &expect).is_some());
        assert!(!p.is_sealed(), "one of two peers served");
        assert!(p.agree_for(&id(2), &eph.public(), &expect).is_some());
        assert!(p.is_sealed(), "secret destroyed once all channels are open");
        assert!(p.agree_for(&id(3), &eph.public(), &expect).is_none());
    }

    #[test]
    fn serving_one_peer_twice_does_not_seal() {
        // The defect a use counter has: the same peer re-establishing would
        // retire a generation another member still needs.
        let mut p = PrekeyPool::new().unwrap();
        let eph = DhSecret::generate().unwrap();
        let expect: BTreeSet<SigPublic> = [id(1), id(2)].into_iter().collect();
        p.agree_for(&id(1), &eph.public(), &expect);
        p.agree_for(&id(1), &eph.public(), &expect);
        assert!(!p.is_sealed());
        assert!(p.agree_for(&id(2), &eph.public(), &expect).is_some());
        assert!(p.is_sealed());
    }

    #[test]
    fn envelopes_do_not_bring_sealing_forward() {
        let mut p = PrekeyPool::new().unwrap();
        let eph = DhSecret::generate().unwrap();
        let expect: BTreeSet<SigPublic> = [id(1)].into_iter().collect();
        assert!(p.agree_envelope(&eph.public()).is_some());
        assert!(!p.is_sealed());
        p.agree_for(&id(1), &eph.public(), &expect);
        assert!(p.is_sealed());
        assert!(p.agree_envelope(&eph.public()).is_none());
    }

    #[test]
    fn deadline_seals_a_stalled_generation() {
        let mut p = PrekeyPool::new().unwrap();
        for _ in 0..SEAL_AFTER {
            p.tick();
        }
        assert!(p.is_sealed(), "a silent peer must not extend the horizon");
    }

    #[test]
    fn rotation_advances_and_destroys() {
        let mut p = PrekeyPool::new().unwrap();
        let old_pub = p.public();
        p.rotate().unwrap();
        assert_eq!(p.generation(), 1);
        assert_ne!(p.public(), old_pub);
        assert!(!p.is_sealed());
    }

    #[test]
    fn agreement_matches_the_peer_side() {
        let mut p = PrekeyPool::new().unwrap();
        let eph = DhSecret::generate().unwrap();
        let theirs = eph.agree(&p.public()).unwrap();
        let ours = p
            .agree_for(&id(1), &eph.public(), &[id(1)].into_iter().collect())
            .unwrap();
        assert_eq!(ours, theirs);
    }
}
