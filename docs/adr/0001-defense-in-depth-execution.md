# ADR 0001: Defense-in-depth execution authorization

- Status: accepted
- Date: 2026-08-11

## Context

An MCP client can be prompt-injected, malicious, or simply wrong about authorization. A
single caller-provided boolean or target string is therefore insufficient to authorize
local repository access. Database-only authorization is also vulnerable to state
tampering, and path checks performed separately from file opening leave a race window.

## Decision

Every execute operation requires all of the following:

1. an operator-created execute engagement;
2. an active, unexpired grant containing the operation-specific capability;
3. a canonical target inside engagement scope;
4. any operation-specific operator allowlist;
5. `SCOPEGUARD_EXECUTION_ENABLED=true` in the server environment;
6. a valid HMAC-sealed audit checkpoint when sealed execution is required; and
7. a fixed, bounded implementation rather than an arbitrary execution primitive.

Repository scans additionally require membership under an allowed root and bounded,
no-follow file access. Network probes additionally require the independent network gate,
hostname and resolved-address allowlists, one pinned DNS answer, strict time/port limits,
and fixed HEAD, TLS-handshake, or connect-only behavior.

MCP callers may create and revoke dry-run engagements but cannot create or revoke execute
grants. The server exposes no arbitrary command, subprocess, network-request, or dynamic
code primitive.

## Consequences

- Accidental execution requires several independent operator-controlled conditions.
- Database tampering alone does not enable production execution when sealed auditing is
  required.
- Operations need secret-key management, explicit rotation, and external audit anchoring.
- Unsupported platforms receive a documented best-effort file-opening fallback.
- Adding an external analyzer or network action requires a new capability, fixed
  arguments, limits, redaction, evidence design, and negative tests rather than a generic
  shell or request adapter.
