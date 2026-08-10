# ScopeGuard MCP

[![CI](https://github.com/mzatylny/scopeguard-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/mzatylny/scopeguard-mcp/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-2.0-purple.svg)](https://modelcontextprotocol.io/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

ScopeGuard is a policy-first defensive security operations server for MCP. It gives AI
clients useful repository and web-security analysis while keeping authorization,
execution, target scope, and auditability under operator control.

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
| Process control | No arbitrary shell or command tool | Broad subprocess wrappers |
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

## Capabilities

| Capability | Allows |
|---|---|
| `plan:assessment` | Bounded web/repository planning for an in-scope target |
| `analyze:headers` | Offline analysis of supplied HTTP headers |
| `scan:repository` | Built-in read-only scan, subject to both execution gates |
| `audit:read` | Reading engagement-specific audit events |

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `SCOPEGUARD_STATE_DIR` | `<cwd>/.scopeguard` | SQLite state and audit database |
| `SCOPEGUARD_ALLOWED_ROOTS` | current directory | Path-separated operator allowlist |
| `SCOPEGUARD_EXECUTION_ENABLED` | `false` | Enables execute engagements when `true` |
| `SCOPEGUARD_MAX_FILES` | `5000` | Repository scan file ceiling |
| `SCOPEGUARD_MAX_FILE_BYTES` | `1000000` | Per-file read ceiling |

The MCP server intentionally exposes only stdio. A future network transport must ship
with standards-based authentication, request-size limits, and explicit deployment
guidance; binding an unauthenticated security service to a port is not accepted here.

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
