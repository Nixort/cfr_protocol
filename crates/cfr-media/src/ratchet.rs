// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Per-sender media ratchets.

use cfr_crypto::{kdf, Secret, SigPublic, KEY_LEN};

/// Frames per ratchet epoch.
pub const EPOCH: u64 = 256;

/// Largest forward epoch jump accepted in one receive operation.
pub const MAX_EPOCH_JUMP: u64 = 1024;

fn base(group: &Secret<KEY_LEN>, sender: &SigPublic) -> Secret<KEY_LEN> {
    kdf(group, b"cfr/media/base", &[sender.as_bytes()])
}

/// The sending side of a sender-specific media ratchet.
pub struct SendRatchet {
    pub(crate) chain: Secret<KEY_LEN>,
    pub(crate) epoch: u64,
}

impl SendRatchet {
    /// Starts a sender chain under `group`.
    pub fn new(group: &Secret<KEY_LEN>, sender: &SigPublic) -> Self {
        Self {
            chain: base(group, sender),
            epoch: 0,
        }
    }

    /// Returns the frame key for `index`, advancing the epoch chain as needed.
    pub fn key(&mut self, index: u64) -> Option<Secret<KEY_LEN>> {
        let target_epoch = index / EPOCH;
        if target_epoch < self.epoch {
            return None;
        }
        while self.epoch < target_epoch {
            let next = kdf(&self.chain, b"cfr/media/epoch", &[]);
            self.chain.wipe();
            self.chain = next;
            self.epoch = self.epoch.checked_add(1)?;
        }
        Some(kdf(
            &self.chain,
            b"cfr/media/frame",
            &[&index.to_be_bytes()],
        ))
    }
}

/// The receiving side of a sender-specific media ratchet.
///
/// The caller commits a cloned instance only after frame authentication.
#[derive(Clone)]
pub struct RecvRatchet {
    pub(crate) chain: Secret<KEY_LEN>,
    pub(crate) epoch: u64,
}

impl RecvRatchet {
    /// Starts a receiver chain under `group`.
    pub fn new(group: &Secret<KEY_LEN>, sender: &SigPublic) -> Self {
        Self {
            chain: base(group, sender),
            epoch: 0,
        }
    }

    /// Returns the current epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the frame key for `index` or rejects stale and excessive jumps.
    pub fn key(&mut self, index: u64) -> Option<Secret<KEY_LEN>> {
        let target_epoch = index / EPOCH;
        if target_epoch < self.epoch || target_epoch - self.epoch > MAX_EPOCH_JUMP {
            return None;
        }
        while self.epoch < target_epoch {
            let next = kdf(&self.chain, b"cfr/media/epoch", &[]);
            self.chain.wipe();
            self.chain = next;
            self.epoch = self.epoch.checked_add(1)?;
        }
        Some(kdf(
            &self.chain,
            b"cfr/media/frame",
            &[&index.to_be_bytes()],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (Secret<KEY_LEN>, SigPublic) {
        (Secret::from([3u8; 32]), SigPublic::from_bytes([9u8; 32]))
    }

    #[test]
    fn both_sides_derive_the_same_frame_key() {
        let (group, sender) = setup();
        let mut tx = SendRatchet::new(&group, &sender);
        let mut rx = RecvRatchet::new(&group, &sender);
        for index in [0u64, 1, 255, 256, 700, 5_000] {
            assert_eq!(tx.key(index), rx.key(index), "index {index}");
        }
    }

    #[test]
    fn a_64_bit_index_works_from_a_synchronized_epoch() {
        let (group, sender) = setup();
        let index = u64::from(u32::MAX) + 1;
        let epoch = index / EPOCH;
        let mut tx = SendRatchet {
            chain: base(&group, &sender),
            epoch,
        };
        let mut rx = RecvRatchet {
            chain: base(&group, &sender),
            epoch,
        };
        assert_eq!(tx.key(index), rx.key(index));
    }

    #[test]
    fn frame_keys_differ_per_index_and_sender() {
        let (group, sender) = setup();
        let mut first = SendRatchet::new(&group, &sender);
        assert_ne!(first.key(0), first.key(1));
        let other = SigPublic::from_bytes([8u8; 32]);
        let mut second = SendRatchet::new(&group, &other);
        let mut third = SendRatchet::new(&group, &sender);
        assert_ne!(third.key(0), second.key(0));
    }

    #[test]
    fn receiver_cannot_go_back_an_epoch() {
        let (group, sender) = setup();
        let mut receiver = RecvRatchet::new(&group, &sender);
        assert!(receiver.key(1_000).is_some());
        assert_eq!(receiver.epoch(), 3);
        assert!(receiver.key(10).is_none());
        assert!(receiver.key(768).is_some());
    }

    #[test]
    fn absurd_jump_is_refused_without_state_change() {
        let (group, sender) = setup();
        let mut receiver = RecvRatchet::new(&group, &sender);
        assert!(receiver.key(u64::MAX).is_none());
        assert_eq!(receiver.epoch(), 0);
    }
}
