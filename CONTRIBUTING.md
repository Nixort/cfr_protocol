# Contributing to CFR

Causal Frontier Ratchet accepts changes only when their security boundary, format impact, and validation evidence are explicit. Keep every patch narrow and reviewable. Use Conventional Commit prefixes: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`, and `build:`.

## Development contract

The supported minimum Rust version is **1.85.0**. The committed `Cargo.lock` is part of that promise; dependency changes must pass the locked MSRV and stable checks. Run the complete local gate before requesting review:

```sh
make check
make hard
make release
```

Warnings are review blockers. The workspace denies `unsafe`; an exception must isolate the boundary, include a `// SAFETY:` proof, describe the changed trust assumption, and add a focused regression. Public APIs need Rust documentation. Modules should remain small and capability-scoped; do not add ambient mutable globals.

## Security- and format-sensitive changes

| Change type | Required evidence |
|---|---|
| Canonical encoding, signed image, operation identifier, KDF/hash label, AEAD associated data, or media trailer | State the compatibility decision, add deterministic vectors, and update the relevant protocol contract |
| Cryptographic dependency or parameter | Preserve algorithm rationale, add regression coverage, run locked stable and MSRV gates |
| Membership, repair, prekey, channel, or ratchet behavior | Add an end-to-end deterministic failure-path regression and explain the changed entitlement boundary |
| Parser or resource limit | Add a minimal fuzz corpus seed or fuzz reproducer when appropriate |

Do not implement cryptographic primitives manually, log keys or plaintext, use production-like credentials in fixtures, accept unbounded attacker-controlled allocation, or alter protocol domain labels as a presentation-only change. Treat network bytes, decoded values, filenames, and every transport message as untrusted until validated.

## Fuzzing

Fuzz targets live in a separate workspace and need nightly Rust plus `cargo-fuzz`:

```sh
make fuzz
```

Keep minimized, non-secret corpus inputs. Do not commit crash artifacts, credentials, plaintext, or generated build output.

## Documentation

Keep the README concise. Update `docs/protocol.md`, `docs/security.md`, or `docs/integration.md` only when the corresponding contract changes. Do not duplicate long-form design rationale in source comments.
