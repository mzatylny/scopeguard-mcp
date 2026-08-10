# ScopeGuard MCP

[![CI](https://github.com/mzatylny/scopeguard-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/mzatylny/scopeguard-mcp/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-2.0-purple.svg)](https://modelcontextprotocol.io/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

ScopeGuard is a policy-first defensive security and bounded posture-testing server for
MCP. It gives AI clients useful repository, HTTP, TLS, and single-host TCP analysis while
keeping authorization, execution, target scope, and auditability under operator control.

It is designed as a safer, maintainable alternative to broad shell-driven pentest
orchestrators. “Better” here means stronger trust boundaries and engineering quality—not
more autonomous exploitation.

The comparison below uses the public
[HexStrike AI v6 repository](https://github.com/0x4m4/hexstrike-ai) as the reference
baseline. ScopeGuard is built on the
[official MCP Python SDK 2.x](https://github.com/modelcontextprotocol/python-sdk).

## Why ScopeGuard

| Boundary | ScopeGuard | HexStrike AI v6 reference inspected |
|---|---|---|
| Protocol | Official MCP Python SDK 2.x | FastMCP dependency below 1.0 |
| Architecture | Small modules with explicit domain boundaries | Two main Python scripts totaling about 22k lines |
| Client transport | Local stdio only | MCP client plus local Flask execution API |
| Authorization | Expiring engagements, target scopes, capabilities | Caller-supplied targets sent to execution endpoints |
| Execution | Operator-created execute engagement **and** server-side environment gate | Tool call can directly launch commands |
| Process control | Fixed built-in analyzers and bounded probes; no arbitrary shell | Broad subprocess wrappers |
| Audit | SQLite WAL plus a verifiable SHA-256 hash chain | Conventional logs |
| Secret handling | Findings are fingerprinted; matched values are never returned | Tool output may contain raw secrets |
| Quality | CI matrix, linting, packaging, 90% coverage floor | No test or CI suite visible in the inspected tree |

ScopeGuard does not include exploit generation, password attacks, payload generation,
credential capture, or autonomous attack-chain execution.

## Included tools

- `health` — safety posture, supported capabilities, and audit-chain status
- `create_dry_run_engagement` — create an expiring, non-executing scope from MCP
- `revoke_engagement` — stop an engagement immediately
- `check_scope` — normalize and evaluate a URL, domain, IP/CIDR, or file target
- `plan_assessment` — produce a bounded web or repository baseline plan
- `analyze_headers` — inspect caller-supplied HTTP headers without making a request
- `scan_repository` — read-only built-in Python risk and secret checks
- `probe_http` — make one allowlisted HEAD request without credentials or redirects
- `inspect_tls` — validate one allowlisted TLS handshake and inspect its certificate
- `probe_tcp_ports` — bounded TCP connects to one allowlisted host without banner capture
- `run_posture_assessment` — run the fixed TCP → TLS → HTTP posture workflow
- `list_audit_events` and `verify_audit_chain` — inspect and verify evidence

## Quick start

Python 3.11 or newer is required.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e .

scopeguard doctor
scopeguard-mcp
```

Configure an MCP client to launch the local stdio server:

```json
{
  "mcpServers": {
    "scopeguard": {
      "command": "/absolute/path/to/scopeguard-mcp/.venv/bin/scopeguard-mcp",
      "env": {
        "SCOPEGUARD_STATE_DIR": "/absolute/path/to/scopeguard-state"
      }
    }
  }
}
```

## Authorization workflow

MCP clients can create only `dry-run` engagements. They can check scope, build plans,
and perform offline header analysis, but repository execution remains planned.

For a real read-only repository scan, the operator must create an execute engagement
outside the model and launch the server with execution enabled:

```bash
export SCOPEGUARD_STATE_DIR=/absolute/path/to/scopeguard-state
export SCOPEGUARD_ALLOWED_ROOTS=/absolute/path/to/authorized-repositories
export SCOPEGUARD_EXECUTION_ENABLED=true

scopeguard create-engagement \
  --title "Repository security baseline" \
  --ticket SEC-1234 \
  --target file:/absolute/path/to/authorized-repositories/example \
  --capability scan:repository \
  --capability audit:read \
  --mode execute \
  --expires-in-minutes 60

scopeguard-mcp
```

The returned engagement ID is required by `scan_repository`. Both the engagement file
scope and `SCOPEGUARD_ALLOWED_ROOTS` must contain the requested path. Symlinks are
resolved before either policy is evaluated.

### Bounded network posture testing

Network probes are off by default and require an additional operator gate. A hostname
must match `SCOPEGUARD_ALLOWED_HOSTS`, and every address returned by DNS must fit
`SCOPEGUARD_ALLOWED_NETWORKS`. Direct IP targets must fit the network allowlist. This
two-part rule prevents a permitted name from resolving to an unexpected address.

```bash
export SCOPEGUARD_STATE_DIR=/absolute/path/to/scopeguard-state
export SCOPEGUARD_EXECUTION_ENABLED=true
export SCOPEGUARD_NETWORK_ENABLED=true
export SCOPEGUARD_ALLOWED_HOSTS=staging.example.com,*.staging.example.com
export SCOPEGUARD_ALLOWED_NETWORKS=192.0.2.0/24,2001:db8::/32

scopeguard create-engagement \
  --title "Authorized staging posture review" \
  --ticket SEC-5678 \
  --target staging.example.com \
  --target https://staging.example.com/ \
  --capability probe:http \
  --capability inspect:tls \
  --capability probe:tcp-ports \
  --capability run:posture-assessment \
  --capability audit:read \
  --mode execute \
  --expires-in-minutes 30

scopeguard-mcp
```

The HTTP tool sends only `HEAD`, does not accept credentials or a request body, pins the
connection to a pre-authorized DNS answer, and never follows redirects. Sensitive
response headers are redacted. The TCP tool accepts at most 32 unique ports by default,
uses connect-only checks, and never sends application data or captures banners.

### Guarded autonomous workflow

`run_posture_assessment` automates only a predeclared posture sequence. Before the first
connection it validates the workflow capability, every underlying probe capability, both
the URL and host scopes, target-host equality, the port limit, the execute gate, and the
network gate. HTTPS runs TCP → TLS → HTTP; HTTP runs TCP → HTTP. The workflow stops at the
first error and records completed steps in the audit chain.

It does not choose new tools or targets from results, exploit findings, submit payloads,
retry with different techniques, or start follow-on actions. A dry-run returns the exact
planned sequence without making a connection.

## Capabilities

| Capability | Allows |
|---|---|
| `plan:assessment` | Bounded web/repository planning for an in-scope target |
| `analyze:headers` | Offline analysis of supplied HTTP headers |
| `scan:repository` | Built-in read-only scan, subject to both execution gates |
| `probe:http` | One allowlisted, no-redirect HTTP HEAD request |
| `inspect:tls` | One allowlisted, certificate-validating TLS handshake |
| `probe:tcp-ports` | Bounded connect-only TCP checks against one host |
| `run:posture-assessment` | Fixed, fail-closed orchestration of the bounded probes |
| `audit:read` | Reading engagement-specific audit events |

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `SCOPEGUARD_STATE_DIR` | `<cwd>/.scopeguard` | SQLite state and audit database |
| `SCOPEGUARD_ALLOWED_ROOTS` | current directory | Path-separated operator allowlist |
| `SCOPEGUARD_EXECUTION_ENABLED` | `false` | Enables execute engagements when `true` |
| `SCOPEGUARD_MAX_FILES` | `5000` | Repository scan file ceiling |
| `SCOPEGUARD_MAX_FILE_BYTES` | `1000000` | Per-file read ceiling |
| `SCOPEGUARD_NETWORK_ENABLED` | `false` | Independently enables bounded network probes |
| `SCOPEGUARD_ALLOWED_HOSTS` | empty | Comma-separated exact or `*.` hostname allowlist |
| `SCOPEGUARD_ALLOWED_NETWORKS` | empty | Comma-separated IP/CIDR allowlist |
| `SCOPEGUARD_MAX_PORTS` | `32` | Unique TCP ports per call; hard ceiling is 128 |
| `SCOPEGUARD_NETWORK_TIMEOUT_SECONDS` | `3` | Per-connection timeout; range is 0.1–10 seconds |

The MCP server itself intentionally exposes only stdio. A future server transport must ship
with standards-based authentication, request-size limits, and explicit deployment
guidance; binding an unauthenticated security service to a port is not accepted here.

## Safety boundary

ScopeGuard supports authorized posture testing, not unrestricted offensive automation.
It does not provide arbitrary requests or commands, password attacks, credential capture,
exploit or payload generation, persistence, evasion, denial of service, CIDR-wide scans,
or autonomous attack chains. The fixed posture runner is defensive orchestration, not an
attack agent; these exclusions are trust boundaries, not missing tools.

## Repository analyzer

The dependency-free analyzer currently detects:

- Python `eval` / `exec`
- `os.system` / `os.popen`
- `subprocess` calls with `shell=True`
- unsafe Pickle deserialization
- `yaml.load` without a safe loader
- private-key blocks, AWS access keys, GitHub tokens, and likely hard-coded secrets

Secret values are never returned. Findings contain only rule metadata, location, and a
short one-way fingerprint for correlation.

## Development

```bash
pip install -e ".[dev]"
ruff check .
pytest
python -m build
```

The test suite includes a real in-memory MCP v2 discovery and tool-call round trip.

See [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md), and
[CONTRIBUTING.md](CONTRIBUTING.md) for design and project policy.

## Responsible use

Use ScopeGuard only on repositories and systems you own or are explicitly authorized to
assess. The project is defensive tooling, not authorization to test a target.
