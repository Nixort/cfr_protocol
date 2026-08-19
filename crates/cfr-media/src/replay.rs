// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Replay suppression per sender.

/// Width of the acceptance window, in frames.
pub const WINDOW: u64 = 64;

/// A sliding replay window over authenticated frame indices.
#[derive(Debug, Default, Clone)]
pub struct Replay {
    high: u64,
    seen: u64,
    started: bool,
}

impl Replay {
    /// Returns a fresh replay window.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `index` when it is inside the forward acceptance window.
    pub fn accept(&mut self, index: u64) -> bool {
        if !self.started {
            self.started = true;
            self.high = index;
            self.seen = 1;
            return true;
        }
        if index > self.high {
            let shift = index - self.high;
            self.seen = if shift >= WINDOW {
                0
            } else {
                self.seen << shift
            };
            self.seen |= 1;
            self.high = index;
            return true;
        }
        let back = self.high - index;
        if back >= WINDOW {
            return false;
        }
        let bit = 1u64 << back;
        if self.seen & bit != 0 {
            return false;
        }
        self.seen |= bit;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_order_frames_are_accepted_once() {
        let mut replay = Replay::new();
        for index in 0..1_000 {
            assert!(replay.accept(index), "{index}");
        }
        for index in 936..1_000 {
            assert!(!replay.accept(index), "replay of {index} must be refused");
        }
    }

    #[test]
    fn out_of_order_within_window_is_accepted_once() {
        let mut replay = Replay::new();
        assert!(replay.accept(10));
        assert!(replay.accept(8));
        assert!(!replay.accept(8));
        assert!(replay.accept(9));
        assert!(!replay.accept(10));
    }

    #[test]
    fn old_frames_are_refused() {
        let mut replay = Replay::new();
        assert!(replay.accept(1_000));
        assert!(!replay.accept(1_000 - WINDOW));
        assert!(replay.accept(1_000 - WINDOW + 1));
    }

    #[test]
    fn large_64_bit_jump_clears_window_without_overflow() {
        let mut replay = Replay::new();
        assert!(replay.accept(0));
        assert!(replay.accept(u64::MAX));
        assert!(!replay.accept(0));
        assert!(!replay.accept(u64::MAX));
    }
}
