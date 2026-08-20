# Changelog

All notable changes will be documented here.

## 1.1.0 - 2026-08-20

- Added operator-gated HTTP HEAD, TLS handshake, and single-host TCP posture probes
- Added independent network execution, hostname, CIDR, timeout, and port-count controls
- Pinned outbound connections to pre-authorized DNS answers to mitigate rebinding
- Added sensitive response-header redaction and a no-redirect HTTP policy
- Added audit evidence and adversarial tests for every network safety boundary
- Added a fixed-sequence, fully preflighted, fail-closed posture assessment runner
- Added offline education-only tabletop simulations locked to `training.invalid`
- Applied the sealed-audit execution gate to every new network execute path

## 1.0.0 - 2026-08-11

- Added HMAC-sealed audit checkpoints with tail-truncation detection and safe export
- Added fail-closed sealed-audit enforcement for operator execute mode
- Added durable scan-run evidence with manifest and ruleset digests
- Added symlink-component-safe file opening on supported POSIX platforms
- Added keyed secret fingerprints and explicit scan truncation reasons
- Added target, header, total-byte, and finding resource ceilings
- Restricted MCP revocation to dry-run engagements
- Added CodeQL, Bandit, dependency auditing, strict typing, SBOM generation, and build
  provenance attestations
- Expanded the threat model, operations runbook, ADRs, and negative tests

## 0.1.0 - 2026-08-10

- Initial MCP v2 stdio server
- Expiring scoped engagements with capability grants
- Operator-only execute engagement creation and environment execution gate
- Offline HTTP security-header analysis
- Read-only Python and secret repository analyzer
- Tamper-evident SQLite audit chain
- CLI, packaging, CI, and comprehensive tests
