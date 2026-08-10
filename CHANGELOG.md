# Changelog

All notable changes will be documented here.

## 0.2.0 - 2026-08-10

- Added operator-gated HTTP HEAD, TLS handshake, and single-host TCP posture probes
- Added independent network execution, hostname, CIDR, timeout, and port-count controls
- Pinned outbound connections to pre-authorized DNS answers to mitigate rebinding
- Added sensitive response-header redaction and a no-redirect HTTP policy
- Added audit evidence and adversarial tests for every network safety boundary
- Added a fixed-sequence, fully preflighted, fail-closed posture assessment runner

## 0.1.0 - 2026-08-10

- Initial MCP v2 stdio server
- Expiring scoped engagements with capability grants
- Operator-only execute engagement creation and environment execution gate
- Offline HTTP security-header analysis
- Read-only Python and secret repository analyzer
- Tamper-evident SQLite audit chain
- CLI, packaging, CI, and comprehensive tests
