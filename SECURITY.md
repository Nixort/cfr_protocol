# Security Policy

## Scope

Causal Frontier Ratchet is security-sensitive software. Reports concerning canonical decoding, signatures, authorization, group-key derivation, prekeys, repair, replay handling, media-frame protection, memory/resource bounds, or secret exposure are in scope.

## Reporting a vulnerability

Do **not** open a public issue for a suspected vulnerability. Contact the maintainer through the private security-reporting channel configured for the repository and include a minimal reproduction, affected revision, attack prerequisites, expected versus actual behavior, and any impact on confidentiality, integrity, availability, or forward secrecy.

Do not include real keys, private conference content, credentials, or production captures. A synthetic reproducer and a redacted trace are sufficient for initial triage.

## Triage and remediation

The project will acknowledge a reproducible report, assess its severity and affected protocol boundary, and coordinate a fix before public disclosure where feasible. A security fix must include a deterministic regression, test evidence, and an explicit compatibility decision when wire bytes, KDF labels, or signed images are affected.

## Supported versions

Security maintenance applies to the current `main` branch until versioned releases and a support matrix are published.
