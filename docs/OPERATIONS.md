# Operations runbook

## Secure initialization

1. Create a dedicated operating-system account or isolated workstation profile.
2. Create a private state directory outside scanned repositories and restrict it to the
   operator account.
3. Generate at least 32 random bytes for `SCOPEGUARD_AUDIT_HMAC_KEY` and load the value
   from a secret manager. Never commit it or pass it as a CLI argument.
4. Give the key a non-secret rotation identifier with `SCOPEGUARD_AUDIT_KEY_ID`.
5. Set `SCOPEGUARD_ALLOWED_ROOTS` to the smallest required directory set.
6. Leave `SCOPEGUARD_NETWORK_ENABLED=false` unless bounded probes are required. When they
   are required, configure the smallest exact/wildcard hostname set and IP/CIDR set; both
   allowlists must independently authorize the destination.
7. Run `scopeguard doctor` and require `ok: true`, `audit_chain.valid: true`, and
   `execution_ready: true` before creating an execute engagement.

## Before an assessment

- Confirm the authorization ticket, target ownership, scope, and expiry with a human.
- Prefer one repository root and the minimum capability set.
- Keep engagement lifetimes short.
- Review configured file, byte, and finding ceilings against repository size.
- For network work, review the hostname patterns, resolved-address ranges, port count,
  timeout, URL/host target equality, and exact fixed workflow before enabling the network
  gate. Confirm all current DNS answers are expected.
- Confirm the state volume has adequate space and is not inside the target repository.

## After an assessment

1. Revoke the execute engagement through the operator CLI and disable the network and
   execution environment gates when they are no longer needed.
2. Run `scopeguard verify-audit`.
3. Export the signed head with `scopeguard export-audit-checkpoint`.
4. Store the checkpoint in an append-only external system with the ticket and scan ID.
5. Retain the SQLite database according to evidence and privacy requirements.

## Backup and restore

Use SQLite's online backup mechanism or copy the database only while both the CLI and MCP
server are stopped. Preserve the database, WAL/SHM files when present, exported audit
heads, key identifier, application version, and configuration limits. After restoration,
run `scopeguard verify-audit` before allowing execution and compare its head with the last
external checkpoint.

## Audit-key rotation

In-place silent key replacement fails closed by design. For rotation:

1. Stop the MCP server.
2. Verify and externally anchor the old database head.
3. Archive the old state database under its retention policy.
4. Create a new empty state directory.
5. load the new key and key identifier, then run `scopeguard doctor`.
6. Create new engagements in the new state database.

This produces an explicit evidence boundary between key generations.

## Incident response

If audit verification fails, an unexpected execute engagement appears, or a secret value
is observed in output:

1. Stop the server and unset both the network and execution gates.
2. Preserve the state database, WAL/SHM files, configuration, process logs, and last
   external checkpoint without modifying them.
3. Revoke or rotate any potentially exposed credential outside ScopeGuard.
4. Compare the database head with external checkpoints and review scan-run transitions.
5. Rebuild in a clean environment before resuming operation.
6. Report a product vulnerability through GitHub private vulnerability reporting.

Do not continue appending events to a database with a failed checkpoint; the storage layer
also rejects this automatically where it can.
