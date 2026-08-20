// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! A hostile in-memory network for the end-to-end tests.

#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::match_single_binding,
    clippy::range_plus_one,
    clippy::single_match,
    clippy::single_match_else,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::should_implement_trait,
    clippy::too_many_lines,
    clippy::uninlined_format_args
)]

use cfr_protocol::{Codec, Conference, Event, Joining, Policy, Recipient, SigPublic};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// A tiny deterministic PRNG. Reproducibility matters more than quality here:
/// a randomized test that cannot be replayed from its seed reports failures
/// nobody can investigate.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed ^ 0x9E37_79B9_7F4A_7C15)
    }
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
    pub fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
    pub fn pick<T: Copy>(&mut self, v: &[T]) -> Option<T> {
        if v.is_empty() {
            None
        } else {
            Some(v[self.below(v.len())])
        }
    }
}

pub struct Net {
    pub peers: BTreeMap<SigPublic, Conference>,
    queue: VecDeque<(SigPublic, Vec<u8>)>,
    pub offline: BTreeSet<SigPublic>,
    /// Peers that have been evicted. Still on the network, no longer members.
    pub evicted: BTreeSet<SigPublic>,
    pub partitions: Vec<BTreeSet<SigPublic>>,
    pub loss_percent: u64,
    pub rng: Rng,
    pub events: Vec<(SigPublic, Event)>,
    pub rejected: usize,
}

impl Net {
    pub fn new(seed: u64) -> Self {
        Self {
            peers: BTreeMap::new(),
            queue: VecDeque::new(),
            offline: BTreeSet::new(),
            evicted: BTreeSet::new(),
            partitions: Vec::new(),
            loss_percent: 0,
            rng: Rng::new(seed),
            events: Vec::new(),
            rejected: 0,
        }
    }

    pub fn founder(seed: u64, policy: Policy) -> (Self, SigPublic) {
        let mut n = Self::new(seed);
        let (c, out) = Conference::create(policy).expect("created");
        let id = c.identity();
        n.peers.insert(id, c);
        n.send(id, out);
        n.settle();
        (n, id)
    }

    fn reachable(&self, from: &SigPublic, to: &SigPublic) -> bool {
        if self.offline.contains(to) {
            return false;
        }
        if self.partitions.is_empty() {
            return true;
        }
        let g = |x: &SigPublic| self.partitions.iter().find(|s| s.contains(x));
        match (g(from), g(to)) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    }

    pub fn send(&mut self, from: SigPublic, out: Vec<cfr_protocol::Message>) {
        for m in out {
            let targets: Vec<SigPublic> = match m.to {
                Recipient::Everyone => self.peers.keys().filter(|k| **k != from).copied().collect(),
                Recipient::Peer(p) => vec![p],
            };
            for t in targets {
                if !self.peers.contains_key(&t) || !self.reachable(&from, &t) {
                    continue;
                }
                if self.loss_percent > 0 && self.rng.chance(self.loss_percent) {
                    continue;
                }
                self.queue.push_back((t, m.payload.clone()));
            }
        }
    }

    pub fn settle(&mut self) {
        for _ in 0..50_000 {
            let Some((to, payload)) = self.queue.pop_front() else {
                return;
            };
            let Some(p) = self.peers.get_mut(&to) else {
                continue;
            };
            match p.handle(&payload) {
                Ok((events, out)) => {
                    for e in events {
                        self.events.push((to, e));
                    }
                    self.send(to, out);
                }
                Err(e) => {
                    self.rejected += 1;
                    if std::env::var("CFR_TRACE").is_ok() {
                        std::eprintln!("reject at {:?}: {:?}", to, e);
                    }
                }
            }
        }
        panic!("network did not settle");
    }

    /// Invites, tolerating an inviter that is not currently able to hand over
    /// the frontier keys. That is a real outcome, not a fault: a participant
    /// mid-repair must refuse to admit someone it cannot give a key to.
    pub fn try_join(&mut self, inviter: SigPublic, policy: Policy) -> Option<SigPublic> {
        if !self.peers.get(&inviter)?.ready() {
            self.act(inviter, Conference::resync);
            self.settle();
        }
        if !self.peers.get(&inviter)?.ready() {
            return None;
        }
        Some(self.join(inviter, policy))
    }

    pub fn join(&mut self, inviter: SigPublic, policy: Policy) -> SigPublic {
        let pending = Joining::new(policy).expect("identity");
        let kp = pending.key_package();
        let id = pending.identity();
        let out = self
            .peers
            .get_mut(&inviter)
            .expect("inviter")
            .invite(&kp)
            .expect("invite");
        let welcome = out
            .iter()
            .find(|m| m.to == Recipient::Peer(id))
            .expect("welcome")
            .payload
            .clone();
        let (c, cout) = pending.accept(&welcome).expect("accept");
        self.peers.insert(id, c);
        self.send(inviter, out);
        self.send(id, cout);
        self.settle();
        self.act(id, |c| c.rekey().unwrap_or_default());
        id
    }

    pub fn act<F>(&mut self, who: SigPublic, f: F)
    where
        F: FnOnce(&mut Conference) -> Vec<cfr_protocol::Message>,
    {
        let out = f(self.peers.get_mut(&who).expect("member"));
        self.send(who, out);
        self.settle();
    }

    pub fn rekey(&mut self, who: SigPublic) {
        self.act(who, |c| c.rekey().unwrap_or_default());
    }

    pub fn resync(&mut self, who: SigPublic) {
        self.act(who, Conference::resync);
    }

    pub fn ids(&self) -> Vec<SigPublic> {
        self.peers.keys().copied().collect()
    }

    pub fn online(&self) -> Vec<SigPublic> {
        self.peers
            .keys()
            .filter(|k| !self.offline.contains(k) && !self.evicted.contains(k))
            .copied()
            .collect()
    }

    /// Everybody who can currently see everybody else agrees on one key.
    pub fn assert_agreement(&mut self, ctx: &str) {
        let ids = self.online();
        assert!(!ids.is_empty());
        // Compare by an observable rather than by reaching into state: two
        // participants agree if a frame from one opens at the other.
        let sender = match ids.iter().find(|i| self.peers[i].ready()) {
            Some(s) => *s,
            None => {
                let diag: Vec<String> = ids
                    .iter()
                    .map(|i| {
                        format!(
                            "{:?}=v{} repair={} members={} ops={}",
                            i,
                            hex::encode(self.peers[i].version()),
                            self.peers[i].needs_repair(),
                            self.peers[i].members().len(),
                            self.peers[i].history_len()
                        )
                    })
                    .collect();
                panic!(
                    "{ctx}: no participant can derive a key\n  {}",
                    diag.join("\n  ")
                );
            }
        };
        let frame = b"agreement probe".to_vec();
        let sealed = self
            .peers
            .get_mut(&sender)
            .unwrap()
            .protect(Codec::Generic, &frame, false)
            .unwrap_or_else(|e| panic!("{ctx}: sender cannot protect: {e:?}"));
        for id in ids.iter().filter(|i| **i != sender) {
            let got = self.peers.get_mut(id).unwrap().open(&sealed);
            match got {
                Ok((from, plain)) => {
                    assert_eq!(from, sender, "{ctx}");
                    assert_eq!(plain, frame, "{ctx}");
                }
                Err(e) => {
                    let diag: Vec<String> = ids
                        .iter()
                        .map(|i| {
                            format!(
                                "{:?}=v{} ready={} repair={} members={} ops={}",
                                i,
                                hex::encode(self.peers[i].version()),
                                self.peers[i].ready(),
                                self.peers[i].needs_repair(),
                                self.peers[i].members().len(),
                                self.peers[i].history_len()
                            )
                        })
                        .collect();
                    panic!(
                        "{ctx}: {id:?} cannot open from {sender:?}: {e:?}\n  {}",
                        diag.join("\n  ")
                    );
                }
            }
        }
        let versions: BTreeSet<[u8; 8]> = ids.iter().map(|i| self.peers[i].version()).collect();
        assert_eq!(versions.len(), 1, "{ctx}: versions diverged");
    }
}
