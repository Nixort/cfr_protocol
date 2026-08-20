// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Pairwise ratcheted contribution channels.
use crate::error::{Error, Result};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use cfr_crypto::{kdf, Secret, KEY_LEN};

/// Ceiling on buffered out-of-order ciphertexts per channel.
pub const MAX_BUFFERED: usize = 64;

/// One direction of a pairwise channel.
pub struct Chan {
    pub(crate) chain: Secret<KEY_LEN>,
    pub(crate) next: u64,
}

impl Chan {
    /// Opens a channel from a root secret.
    pub fn new(root: &Secret<KEY_LEN>) -> Self {
        Self {
            chain: kdf(root, b"cfr/channel/chain", &[]),
            next: 0,
        }
    }

    /// Returns the next message index.
    pub fn position(&self) -> u64 {
        self.next
    }

    /// Derives the key for the current index without changing state.
    fn current_key(&self) -> Secret<KEY_LEN> {
        kdf(
            &self.chain,
            b"cfr/channel/message",
            &[&self.next.to_be_bytes()],
        )
    }

    /// Commits an authenticated ratchet step.
    fn advance(&mut self) -> Result<()> {
        let next_index = self
            .next
            .checked_add(1)
            .ok_or(Error::LimitExceeded("channel message index exhausted"))?;
        let next = kdf(
            &self.chain,
            b"cfr/channel/next",
            &[&self.next.to_be_bytes()],
        );
        self.chain.wipe();
        self.chain = next;
        self.next = next_index;
        Ok(())
    }

    /// Advances the sending ratchet and returns the index with its message key.
    pub fn step(&mut self) -> Result<(u64, Secret<KEY_LEN>)> {
        if self.next == u64::MAX {
            return Err(Error::LimitExceeded("channel message index exhausted"));
        }
        let index = self.next;
        let message_key = self.current_key();
        self.advance()?;
        Ok((index, message_key))
    }
}

/// The receiving side: a ratchet plus a bounded reordering buffer.
pub struct RecvChan {
    pub(crate) chan: Chan,
    pub(crate) buffer: BTreeMap<u64, Vec<u8>>,
}

impl RecvChan {
    /// Opens a receiving channel from a root secret.
    pub fn new(root: &Secret<KEY_LEN>) -> Self {
        Self {
            chan: Chan::new(root),
            buffer: BTreeMap::new(),
        }
    }

    /// Returns the index currently awaited by the channel.
    pub fn position(&self) -> u64 {
        self.chan.position()
    }

    /// Returns the number of buffered out-of-order items.
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// Offers ciphertext for `index`.
    ///
    /// The returned key does not commit state. Call [`Self::commit`] only after
    /// authenticating the payload. Future data is buffered and past data is
    /// ignored as replay.
    pub fn offer(&mut self, index: u64, payload: &[u8]) -> Option<Secret<KEY_LEN>> {
        if index < self.chan.position() {
            return None;
        }
        if index > self.chan.position() {
            if self.buffer.len() < MAX_BUFFERED {
                self.buffer.entry(index).or_insert_with(|| payload.to_vec());
            }
            return None;
        }
        if index == u64::MAX {
            return None;
        }
        Some(self.chan.current_key())
    }

    /// Commits the currently awaited index after successful authentication.
    ///
    /// Returns `false` for a stale callback and errors before counter wrap.
    pub fn commit(&mut self, index: u64) -> Result<bool> {
        if index != self.chan.position() {
            return Ok(false);
        }
        self.chan.advance()?;
        Ok(true)
    }

    /// Takes the buffered ciphertext at the currently awaited index.
    pub fn take_next(&mut self) -> Option<(u64, Vec<u8>, Secret<KEY_LEN>)> {
        let index = self.chan.position();
        if index == u64::MAX {
            return None;
        }
        let payload = self.buffer.remove(&index)?;
        Some((index, payload, self.chan.current_key()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> Secret<KEY_LEN> {
        Secret::from([7u8; 32])
    }

    #[test]
    fn both_ends_agree_step_by_step() {
        let mut sender = Chan::new(&root());
        let mut receiver = RecvChan::new(&root());
        for expected_index in 0..8 {
            let (index, sender_key) = sender.step().expect("index available");
            assert_eq!(index, expected_index);
            let receiver_key = receiver.offer(index, b"ct").expect("current index");
            assert_eq!(sender_key, receiver_key);
            assert!(receiver.commit(index).expect("commit"));
        }
    }

    #[test]
    fn message_keys_are_distinct_per_index() {
        let mut sender = Chan::new(&root());
        let first = sender.step().expect("first").1;
        let second = sender.step().expect("second").1;
        assert_ne!(first, second);
    }

    #[test]
    fn out_of_order_is_buffered_not_cached() {
        let mut sender = Chan::new(&root());
        let first_key = sender.step().expect("first").1;
        let second_key = sender.step().expect("second").1;

        let mut receiver = RecvChan::new(&root());
        assert!(receiver.offer(1, b"one").is_none());
        assert_eq!(receiver.buffered(), 1);
        assert_eq!(receiver.position(), 0, "ratchet has not advanced");

        assert_eq!(
            receiver.offer(0, b"zero").expect("current index"),
            first_key
        );
        assert!(receiver.commit(0).expect("commit"));
        let (index, payload, message_key) = receiver.take_next().expect("buffered index");
        assert_eq!(index, 1);
        assert_eq!(payload, b"one");
        assert_eq!(message_key, second_key);
        assert!(receiver.commit(index).expect("commit"));
        assert_eq!(receiver.buffered(), 0);
    }

    #[test]
    fn rejected_current_payload_does_not_consume_the_ratchet() {
        let mut sender = Chan::new(&root());
        let (index, expected_key) = sender.step().expect("index available");
        let mut receiver = RecvChan::new(&root());

        let rejected_key = receiver.offer(index, b"forged").expect("current index");
        assert_eq!(rejected_key, expected_key);
        assert_eq!(receiver.position(), index);

        let genuine_key = receiver.offer(index, b"genuine").expect("current index");
        assert_eq!(genuine_key, expected_key);
        assert!(receiver.commit(index).expect("commit"));
        assert_eq!(receiver.position(), index + 1);
    }

    #[test]
    fn replay_of_a_committed_index_is_dropped() {
        let mut receiver = RecvChan::new(&root());
        assert!(receiver.offer(0, b"a").is_some());
        assert!(receiver.commit(0).expect("commit"));
        assert!(receiver.offer(0, b"a").is_none());
    }

    #[test]
    fn buffer_is_bounded() {
        let mut receiver = RecvChan::new(&root());
        let upper_bound = u64::try_from(MAX_BUFFERED).expect("buffer limit fits in u64") + 50;
        for index in 1..upper_bound {
            receiver.offer(index, b"x");
        }
        assert!(receiver.buffered() <= MAX_BUFFERED);
    }

    #[test]
    fn a_captured_chain_key_cannot_reach_the_past() {
        let mut sender = Chan::new(&root());
        let first_key = sender.step().expect("first").1;
        let _second_key = sender.step().expect("second").1;
        let snapshot = Chan {
            chain: sender.chain.clone(),
            next: sender.next,
        };
        let mut probe = snapshot;
        for _ in 0..8 {
            assert_ne!(probe.step().expect("available").1, first_key);
        }
    }

    #[test]
    fn index_exhaustion_refuses_wrap_without_changing_chain_state() {
        let mut sender = Chan {
            chain: kdf(&root(), b"cfr/channel/chain", &[]),
            next: u64::MAX,
        };
        let before = sender.chain.clone();
        assert_eq!(
            sender.step(),
            Err(Error::LimitExceeded("channel message index exhausted"))
        );
        assert_eq!(sender.position(), u64::MAX);
        assert_eq!(sender.chain, before);
    }
}
