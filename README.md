# Causal Frontier Ratchet (CFR)

A leaderless **causal-frontier group key agreement** with ratcheted channels
and codec-aware media protection for video conferences, implemented in Rust.
The name describes its two core algorithms: signed operations form a causal
graph whose frontier derives the group key, while channel and media keys ratchet
forward for forward secrecy.

```toml
[dependencies]
cfr = "1.0.0-rc.1"
```

```rust
use cfr::{Codec, Conference, Policy, Recipient};

// Alice starts a conference.
let (mut alice, _bootstrap) = Conference::create(Policy::leaderless(2))?;

// Bob generates identity material out of band and hands over his package.
let bob = cfr::Joining::new(Policy::leaderless(2))?;
let out = alice.invite(&bob.key_package())?;

let welcome = out.iter()
    .find(|m| m.to == Recipient::Peer(bob.identity()))
    .expect("welcome");
let (mut bob, _) = bob.accept(&welcome.payload)?;

// Media.
let frame = [0, 0, 0, 1, 0x65, 0xDE, 0xAD];
let sealed = alice.protect(Codec::H264, &frame, true)?;
let (from, plain) = bob.open(&sealed)?;
```

## What it is

A **continuous group key agreement** with a media layer. Participants publish
signed operations into a causal graph; contributions carry fresh entropy sealed
individually to each recipient; the group key is derived from the graph's
frontier. Anyone can contribute, admit, evict or repair at any time.

| property | how |
|---|---|
| forward secrecy | prekey secrets destroyed once channels open; chain keys overwritten every step |
| post-compromise security | rotate a prekey, contribute once |
| leaderless | no coordinator, no tree root, no distinguished participant |
| agreement | the key version is a pure function of the operations received |
| malicious insiders | equivocation produces transferable proof and eviction |
| untrusted servers | servers may drop, reorder, duplicate, partition and inject |

Media encryption is **codec aware**: frames are encrypted in place, so NAL
headers, OBU headers and the VP8 uncompressed chunk stay readable and
authenticated. A selective forwarding unit keeps routing and dropping frames
without holding any key, and cannot alter a byte of what it reads.

## Layout

| crate | contents |
|---|---|
| `cfr` | the `Conference` type: one participant's whole view of a call |
| `cfr-core` | the key management construction |
| `cfr-media` | codec-aware frame protection |
| `cfr-crypto` | primitives, all from established crates |

Each is usable alone.

## Primitives

Nothing here is homemade.

| role | primitive | crate |
|---|---|---|
| AEAD | AEGIS-256 | [`aegis`](https://crates.io/crates/aegis) |
| hash, KDF, MAC | BLAKE3 | [`blake3`](https://crates.io/crates/blake3) |
| key agreement | X25519 | [`x25519-dalek`](https://crates.io/crates/x25519-dalek) |
| signature | Ed25519 | [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek) |
| KEM (`pq`) | ML-KEM-768 | [`ml-kem`](https://crates.io/crates/ml-kem) |
| erasure | — | [`zeroize`](https://crates.io/crates/zeroize) |
| constant time | — | [`subtle`](https://crates.io/crates/subtle) |

The AEGIS-256 implementation is pinned to the official CFRG draft test vectors
in `cfr-crypto`, so a dependency update that changes the cipher fails the
build rather than the call.

## Features

| feature | effect |
|---|---|
| `std` *(default)* | standard library and `cfr::persistence`; without it the crates are `no_std` + `alloc` |
| `hwaes` *(default)* | AEGIS-256 with hardware AES; needs a C compiler |
| `portable` | AEGIS-256 in pure Rust, no C toolchain |
| `pq` | X25519 + ML-KEM-768 hybrid |

## Testing

```bash
cargo test --workspace                     # 180 passing tests; one ignored timing profile
cargo test -p cfr --release             # includes the randomized suite
cargo +nightly fuzz run codec_canonical    # six coverage-guided targets
cargo run -p cfr --release --example scale
```

The randomized suite runs a hostile network — loss, reordering, partition,
eviction, bit-flipped injection — and checks five invariants after every step.
The default sweep is 12 seeds; `CFR_FUZZ_SEEDS` and `CFR_FUZZ_STEPS`
raise it. A 120-seed, 90-step sweep performs about 220 000 checks.

## Documentation

* [`docs/protocol.md`](docs/protocol.md) — construction and wire format
* [`docs/security.md`](docs/security.md) — threat model and security boundaries
* [`docs/integration.md`](docs/integration.md) — application integration

Read `docs/security.md` before deploying. CFR retains signed causal dependencies
for the active session and never performs local destructive history compaction.

## Licence

GPL-3.0-only.
