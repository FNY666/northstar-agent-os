# Audit trail: sessions, events and durable history

Every governed run in Northstar writes down what it did. This page connects
the three audit surfaces so an operator can follow a single decision from the
model turn to the on-disk record.

## 1. Runtime session transcripts (JSONL)

The runtime appends one JSON object per line to an **append-only transcript**
per session (see `sessions.py`). The transcript is the run's own memory:
events, tool calls, permission decisions, budget accounting, compaction
summaries and the final result are all recorded there — including **before**
the run reports success, so a crash still leaves the decision trail behind.

`cli.py` exposes `sessions` subcommands to list, view, verify and replay
transcripts read-only. `replay`/`timeline` selects an index/type slice; it never
executes tools or model calls. Subagent runs nest as spans and are recorded too,
so a delegation tree is auditable end to end. Mutating path-shaped tool calls
add a `workspace_change` record with pre/post metadata hashes; when the host
supplies a receipt secret, the same call also produces a signed `action_receipt`
record.
Tools may attach a validated bounded artifact manifest for non-path outputs;
that manifest is an observation carried by the receipt, not host attestation.
A host can additionally bind the receipt to a verified authorization grant via
`northstar.receipt-binding.v1`; the runtime records the exact grant-token digest
without receiving the token or its secret. The separate [reversible execution contract](reversible-execution.md) stores
bounded file snapshots for recovery rather than putting file bytes in every
receipt. An opt-in runtime `CheckpointPolicy` records each automatic boundary
as an informational transcript record and exposes its bounded metadata in the
run report; it does not turn checkpoint creation into an automatic rewind.

An opt-in `northstar.session-chain.v1` binds each persisted record to the
previous record digest, starting at an all-zero SHA-256 genesis value. The
runtime and `sessions verify` command can validate the chain without writing;
a secret supplied only through SDK memory or an environment variable adds
HMAC-SHA256 authentication. Hash-only mode detects accidental corruption but
is not an adversarial tamper guarantee. A torn final JSONL line is still
skipped and counted before the intact prefix is checked, while an integrity
record that exceeds the legacy size limit is rejected rather than truncated.
Chained writers automatically reconcile the tail and next index under a POSIX
advisory lock; unsigned transcripts can opt into the same local lock. This is
same-host per-session recovery, not distributed writer coordination, remote
lineage, retention, or a compliance store.

## 2. Durable-run event store and verification

`northstar-durable-run` generalises the audit surface for long-lived runs:
an append-only `event_store` with checkpoints and leases, a per-call
`action_gateway`, and an independent `verifier` that checks postconditions
after the fact rather than trusting the runner's own report. `trace_metrics`
keeps minimal span/trace numbers, and `evaluation` measures how closely a
recorded run followed the declared plan.

This slice is deliberately a local, standard-library prototype — it proves
the mechanisms a hosted durable-run service would need, on a fixture, with no
network.

## 3. Host receipts and the run contract

At the orchestration boundary, authorization is itself recorded: the host
issues a versioned **receipt** (see `northstar-run-contract`) describing what
was authorized — request, mode, ceilings — and the verified runner executes
against that receipt. The contract is the *structural* part of the audit
trail: what could not be changed after signing.

## 4. Export: one canonical NDJSON audit feed (audit v1)

The three surfaces above converge into a single machine boundary for SIEM and
analytics pipelines: an append-style NDJSON **audit feed** whose envelope is
versioned and validated strictly. The normative envelope lives in
`northstar-run-contract` (`audit.py`, `audit.ndjson/1`); producers may not add
envelope fields without a schema revision, and a reader rejects unknown
fields instead of silently ignoring them.

| Field | Kind | Meaning |
| --- | --- | --- |
| `schema_version` | required | `audit.ndjson/1`; readers accept exactly this version |
| `component` | required | producer, e.g. `northstar-agent-runtime` |
| `event` | required | producer event name (session record type / store event type / decision) |
| `ts` | required | RFC 3339 UTC (`Z`), second or millisecond precision |
| `level` | required | `info` \| `notice` \| `error` |
| `payload` | required | producer-specific object (open by design) |
| `seq` | optional | per-producer monotonic sequence |
| `session_id` / `run_id` / `actor_id` | optional | correlation identifiers |

Producer bridges (each with tests):

- **Runtime** — `sessions export <session-id> --session-dir DIR` replays a
  JSONL transcript as canonical NDJSON on stdout; `audit_export.py` mirrors
  the envelope locally because the runtime is deliberately dependency-free.
  `error` level = denials, failed tool results, `error_*` results.
- **Durable-run** — `durable_audit.event_to_audit` maps every EventStore event
  (`EventContract`) into the feed, keeping the event identity
  (`event_id`/`task_id`/`run_id`/`step_id`/`trace_id`/digest) inside `payload`;
  failed/denied/error statuses raise the level to `error`.
- **Host** — `host_audit.authorization_to_audit` maps a *verified*
  authorization grant (actor, run, workspace, capabilities, policy revision,
  expiry) into the feed as `authorization_grant`. Tampered tokens are errors
  at verification time, never audit records.

Shipping to a SIEM is a transport concern: forward the NDJSON stream with
fluent-bit or rsyslog (file → TCP/TLS), tag by `component`, index on `ts`, and
keep `schema_version` as the routing key for schema evolution. The feed is
append-only by construction on the producer side and never re-stamped: `ts`
is the record's original timestamp.

## Honest ceiling

Transcripts and stores are a **local audit trail, not a compliance store**:
individual action receipts and, when enabled, a per-session transcript chain
can be HMAC-verified when a secret is supplied. Local POSIX writer reconciliation
exists for one transcript file, but there is no global transcript lineage,
distributed/remote replication, or retention policy.
The roadmap's P3-1 is delivered in two batches: the audit feed above
(`audit.ndjson/1`) and policy schema-isation (`northstar-policy.toml` versioning,
`northstar.policy.v1` with revision tracking). Later T20 transport work remains
outside this local audit boundary.

## Reading on

- Runtime: [Sessions, compaction, tracing](../../components/northstar-agent-runtime/README.md#sessions-compaction-tracing)
  and `sessions.py` / `session_view.py` in
  [docs/api/northstar-agent-runtime.md](../api/northstar-agent-runtime.md).
- Durable-run README: [Local example](../../components/northstar-durable-run/README.md#local-example)
  walks the event-store flow; API reference in
  [docs/api/northstar-durable-run.md](../api/northstar-durable-run.md).
- Contract: [docs/api/northstar-run-contract.md](../api/northstar-run-contract.md)
  and the [handoff-and-contracts](handoff-and-contracts.md) concept page.
