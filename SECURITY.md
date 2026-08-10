# Security policy

## Supported versions

ScopeGuard is currently pre-1.0. Security fixes are applied to the latest release and the
default branch.

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
- a second environment-controlled execution gate
- an independent network execution gate
- expiring capability grants
- canonical target and path scope checks
- symlink resolution and operator root allowlists
- bounded file count and file size
- hostname plus resolved-address network allowlists
- fixed HTTP HEAD, TLS handshake, and connect-only TCP probes with strict limits
- fixed-sequence posture orchestration with full preflight and fail-closed execution
- no arbitrary subprocess, shell, request, exploit, password, payload, or dynamic-code tool
- redacted secret findings
- tamper-evident audit verification

## Known limitations

- The audit chain lives in the same local trust domain as the database. An administrator
  who can replace the whole database can create a new chain. Export signed audit heads to
  an external system for stronger non-repudiation.
- The built-in scanner is a focused baseline, not a replacement for Semgrep, CodeQL,
  Gitleaks, Trivy, or professional review.
- File scanning trusts the local operating system's discretionary access controls.
- HTTP probing intentionally does not follow redirects, send bodies, or support
  authentication. TLS probing requires a certificate-validating handshake.
- TCP results distinguish only `open` from `closed-or-filtered`; they do not identify
  services and are not a replacement for a reviewed professional assessment.
- The posture runner does not make risk-based decisions, select targets or techniques,
  exploit findings, or retry failed probes. It is deliberately not an attack agent.
- ScopeGuard does not establish that a ticket represents legal authorization; the human
  operator remains responsible for verifying it.

## Out of scope by design

Exploit generation, password attacks, credential collection, payload generation,
persistence, evasion, denial of service, internet-scale scanning, and autonomous attack
chains are not accepted features.
