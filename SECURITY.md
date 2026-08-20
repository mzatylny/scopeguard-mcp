# Security policy

## Supported versions

Security fixes are applied to the latest 1.x release and the default branch.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose secrets, bypass scope,
enable execution, or weaken the audit chain. Use GitHub's private vulnerability reporting
for this repository. Include the affected version, impact, reproduction steps, and a
minimal proof of concept that does not target third-party systems.

## Threat model

ScopeGuard assumes the MCP client may be prompt-injected or actively malicious. It does
not treat model-generated text, target strings, file paths, or engagement mode requests as
operator authorization.

The primary controls are:

- stdio-only transport
- MCP-created engagements forced to dry-run
- operator-only execute engagement creation
- operator-only revocation of execute engagements
- a second environment-controlled execution gate
- an independent network execution gate
- an optional mandatory HMAC-sealed audit gate for every execute operation
- expiring capability grants
- canonical target and path scope checks
- operator root allowlists and no-follow file opening on supported POSIX platforms
- bounded file count, file size, total bytes, findings, targets, and header input
- hostname plus resolved-address network allowlists
- fixed HTTP HEAD, TLS handshake, and connect-only TCP probes with strict limits
- fixed-sequence posture orchestration with full preflight, one pinned DNS result, and
  fail-closed execution
- offline education simulation restricted to dry-run mode and `training.invalid`
- no arbitrary subprocess, shell, request, exploit, password, payload, or dynamic-code tool
- HMAC-fingerprinted secret findings with raw values excluded
- durable scan manifests and ruleset digests
- hash-chained events plus an HMAC-sealed audit checkpoint

## Known limitations

- The first seal of a database can attest only to the state visible at migration time.
  Export each later signed head to an external append-only system to detect full database
  rollback or replacement.
- Key rotation is an operator procedure: archive the last externally anchored checkpoint,
  start a fresh state database with the new key, and retain both evidence sets. In-place
  silent key replacement intentionally fails closed.
- The built-in scanner is a focused baseline, not a replacement for Semgrep, CodeQL,
  Gitleaks, Trivy, or professional review.
- File scanning relies on the local operating system's discretionary access controls.
  Platforms without relative no-follow file opening receive a stricter best-effort path
  check but not the same race resistance as supported POSIX systems.
- HTTP probing intentionally does not follow redirects, send bodies, or support
  authentication. TLS probing requires a certificate-validating handshake.
- TCP results distinguish only `open` from `closed-or-filtered`; they do not identify
  services and are not a replacement for a reviewed professional assessment.
- The posture runner does not make risk-based decisions, select targets or techniques,
  exploit findings, or retry failed probes. It is deliberately not an attack agent.
- Education scenarios are static defensive table-tops with no network, filesystem,
  command, payload, credential, or real-target input path. An education label never
  enables otherwise excluded operational behavior.
- ScopeGuard does not establish that a ticket represents legal authorization; the human
  operator remains responsible for verifying it.

## Out of scope by design

Exploit generation, password attacks, credential collection, payload generation,
persistence, evasion, denial of service, internet-scale scanning, and autonomous attack
chains are not accepted features.
