# Threat model

## Objective

ScopeGuard lets an untrusted or prompt-injected MCP client request useful defensive
analysis without turning that client into a general-purpose security operator. The main
security objective is to ensure that only a human-authorized target, capability, time
window, and execution mode can reach local repository content.

## Assets

- source code and configuration inside authorized repositories
- secret material accidentally present in scanned files
- engagement definitions and authorization tickets
- audit events, signed checkpoints, and scan evidence
- the audit HMAC key and operator environment
- availability of the local MCP process and state database

## Trust boundaries

| Boundary | Trusted for | Not trusted for |
|---|---|---|
| MCP client | Supplying typed requests | Authorization, target scope, execution mode |
| Operator CLI | Creating and revoking execute grants | Proving legal authority by itself |
| Environment | Execution switch, roots, limits, audit key | Protection after host compromise |
| Policy engine | Canonical authorization decisions | Establishing external asset ownership |
| Analyzer | Bounded local reads and structured findings | Comprehensive vulnerability coverage |
| SQLite state | Coordination and durability | Non-repudiation without an external anchor |

## Threats and controls

| Threat | Primary controls | Residual risk |
|---|---|---|
| Prompt injection requests execution | MCP creates dry-run only; execute mode is CLI-only; environment gate | Compromised operator account can authorize work |
| Scope bypass using URLs or paths | Canonical URL/domain/IP/CIDR/path forms; exact origin/path rules; root allowlist | New target types require separate review |
| Symlink or path-replacement race | Canonical authorization plus relative no-follow file opening on supported POSIX systems | Fallback platforms have weaker race resistance |
| Repository resource exhaustion | File, per-file byte, total-byte, and finding ceilings | Large allowed limits can still consume noticeable CPU |
| Header-input memory abuse or injection | Header count/byte ceilings; CR/LF rejection; offline-only analysis | Caller controls non-sensitive header content |
| Secret disclosure in findings | Raw matches excluded; keyed HMAC fingerprints; generic analysis errors | File paths and finding locations remain visible |
| Audit row modification or deletion | Canonical hash chain; event-count/head checkpoint; HMAC signature | Full rollback is detected only against an external anchor |
| Database mutation grants execute access | Execute mode still needs environment gate and optionally a valid sealed audit | Host compromise exposing the audit key defeats this layer |
| MCP denial-of-service by revocation | MCP can revoke only dry-run engagements | Clients can still revoke their own dry-run work |
| Dependency or workflow compromise | Minimal runtime dependency, Dependabot, pip-audit, CodeQL, provenance, SBOM | CI actions referenced by major tags can move within that major |

## Abuse cases tested

- expired and revoked engagement reuse
- missing capability and out-of-scope targets
- duplicate normalized targets and oversized inputs
- URL credentials, invalid ports, traversal, wildcard, and path-prefix confusion
- operator-root escape and symlinked repository files
- dry-run execution, disabled execution, and unsealed execution
- MCP attempts to revoke an execute grant
- secret result redaction and finding-count truncation
- audit row modification, audit tail deletion, and invalid state transitions
- malformed header values containing newline characters

## Explicit non-goals

ScopeGuard does not generate exploits, capture credentials, perform password attacks,
create payloads, establish persistence, evade defenses, run denial-of-service tests, scan
the public internet, or autonomously chain attacks. It is not a substitute for legal
authorization, host isolation, external log retention, or professional security review.
