# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Causal Frontier Ratchet (CFR).
#
# Every target is a thin, reproducible wrapper around an explicit Cargo command.
# `check` is the normal local gate; `hard` adds supply-chain and MSRV checks.

.PHONY: check hard fmt lint test build release msrv audit coverage fuzz bench docs package clean

check: fmt lint test build

hard: check msrv audit package

fmt:
	cargo fmt --all -- --check

lint:
	cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

test:
	cargo test --workspace --all-features --locked

build:
	cargo build --workspace --all-features --locked

release:
	cargo build --release --workspace --all-features --locked

msrv:
	cargo +1.85.0 check --workspace --all-features --locked

audit:
	cargo audit --deny warnings
	cargo deny check all

coverage:
	cargo llvm-cov --workspace --all-features --locked --lcov --output-path lcov.info
	cargo llvm-cov --workspace --all-features --locked --summary-only

package:
	cargo package --allow-dirty --locked --no-verify -p cfr-crypto

# Coverage-guided parser and media fuzzing. Requires nightly Rust and cargo-fuzz;
# each target receives the same bounded execution budget.
fuzz:
	cd fuzz && for target in codec_canonical op_parse message_parse frame_layout frame_open participant_inbound; do \
		cargo +nightly fuzz run $$target -- -max_total_time=60; \
	done

# Runs the current scale benchmark.
bench:
	cargo run -p cfr --release --locked --example scale -- --participants 100 --rounds 200

docs:
	cargo doc --workspace --all-features --no-deps --locked

clean:
	cargo clean
	cd fuzz && cargo clean
