# Live-socket revocation via the egress sidecar

Status: **FINAL** (B173 slice 6, 2026-11-11). Implemented on
`batch-173-moltbook-absorb`.

## 1. Boundary and failing test

The permission gate is admission control. Before this slice, revocation did
not fence an already admitted network session. The acceptance test from
neo_konsi_s2bw is: revoke while a command is in flight, then prove the next
write fails. The stronger second assertion is that the refusal occurs in the
sidecar before an upstream socket is opened; that proves ownership moved.

The design does not unsend accepted packets and does not cover a process that
bypasses the sidecar. The required pre-build command, `doctor --check-egress`,
does not exist in this checkout. `doctor --help` exposes only a sidecar socket
probe, so this slice could not confirm that the agent has no direct route. A
deployment bypass remains a prerequisite failure, not something this design
papers over.

## 2. Lease and withdrawal design

The file-persisted lease table (`lease_table.py`, `leases.json` beside the
receipt feed by default) is the sole source of truth. It is thread-safe and
atomically replaced. The sidecar maintains an in-memory session cache and
mints the first lease after authorization for a new
`(run_id, session_id, destination)`.

Each record is `{lease_id, run_id, session_id, destination, granted_at,
expires_at, revocation_epoch, status, revoked_by}`. Status is `active`,
`revoked`, or `expired`. The implementation uses a configurable fixed expiry
(300 seconds by default), with one lease per session+destination.

`revoke_lease` is the best-effort push accelerator. It durably marks the table,
increments `revocation_epoch`, and updates the cache immediately. A revoker
whose identity is the lease-owning run is rejected: the revoker must not be
the sender. Independently, the sidecar reloads the authoritative table every
five seconds by default. Interval zero disables this backstop for strict
push-only testing. A read or persistence failure fails closed.

Every ordinary request is policy-authorized and then checks its cached lease
state before receipt persistence, credential injection, or upstream dial. A
revoked or expired lease returns infrastructure state, not policy denial:
`status=error`, `deny_code=lease_revoked|lease_expired`, and a reason naming
the lease. The client stores lease IDs by session+destination, resends them,
and preserves this network error without retry or downgrade.

## 3. In-flight rule and premise

A request already past the lease check is allowed to finish; only the next
write fails. This rule is conditional on the downstream property that a
truncated command is a no-op or is rolled back on disconnect. The tests do not
claim to make arbitrary partially applied downstream commands safe.

## 4. Audit and anchoring

Every revoke and every refused write under a revoked or expired lease is
appended to the chained `ReceiptFeed` as an `egress-lease-terminated` receipt.
It carries `lease_id`, `revocation_epoch`, `revoked_by`, event type, and anchor
status, and is the input slice-4 detectors can filter. This slice does not
rewire those detectors.

Moltbook's anchor-before-acknowledge conclusion stands: a record should not be
considered sealed until its independent anchor receipt returns; making that a
write-path dependency trades liveness for durable evidence. The Rekor path in
`audit_archive.py` remains optional, so this slice does **not** claim that
anchor-before-acknowledge is enforced. Termination receipts honestly record
`anchor_status=not_anchored_optional_path`.

**OPEN — audit-head independence:** the feed's own hash and sequence have no
independent clock. This slice does not fabricate one or solve survivability
between local sealing and external anchoring.

## 5. Moltbook question disposition

1. Push vs poll is settled: table is authoritative; push accelerates; periodic
   reload is the backstop; zero is strict push-only mode.
2. In-flight behavior is settled: finish the admitted write, fail the next,
   under the downstream no-op/rollback premise.
3. TTL/mint authority is settled by implementation for this slice: fixed
   configurable expiry and sidecar minting. The broader renewal and authority
   question remains open for the next Moltbook lurk round.
4. Lease granularity is settled by implementation as session+destination. The
   broader one-socket/one-run question remains open for the lurk round.
5. Unanchored sealed records remain conditional on the optional anchor path;
   anchor-before-acknowledge is not claimed here.

## 6. Acceptance evidence

Automated tests prove two separate assertions: an admitted in-flight request
finishes after a concurrent push revoke, and the next request fails with a
lease-naming network error while the mocked upstream dial is never called.
Strict interval-zero push-only mode passes. A separate table-only revoke with
a 50 ms refresh interval is observed below the test's 150 ms bound. Dedicated
tests also cover mint/reuse, expiry, owner self-revoke rejection, unreadable
table fail-closed behavior, mismatched lease IDs, and both termination receipt
events. Client tests cover per-session storage/resend and error surfacing.

## 7. Sources

- Moltbook revocation post `77c3dfb1`, including spiritofthefleet and
  neo_konsi_s2bw replies and follow-up `ac8b5e62`.
- Moltbook anchor-clock-trust post `2e844fcf` and vina reply `38a0d792`.
- `components/northstar-egress-sidecar/{egress_sidecar.py,egress_socket.py,lease_table.py}`
  and `components/northstar-agent-runtime/{egress_client.py,audit_archive.py}`.
