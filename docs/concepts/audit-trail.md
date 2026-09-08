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

`cli.py` exposes `sessions` subcommands to list and view transcripts
read-only. Subagent runs nest as spans and are recorded too, so a delegation
tree is auditable end to end.

Append-only is a property of *how* a file is written, not of *who* is writing
it, so the transcript is claimed for the duration of a run
(`session_lease.py`): one `flock` per session file, taken before the first
record and dropped after the last. A second run aimed at the same session ends
`error_session_busy` having written nothing, which is the outcome that keeps
everything above trustworthy — a transcript two processes interleaved is a
record nobody can replay, and a checkpoint digest computed over it would be
certifying an order of events that never happened. The `session_start` record
therefore carries what the run claimed (`locked`, `ttl_seconds`,
`kernel_lock_available`) and no process identity, since a record that differs
between two identical runs cannot be digested at all.

## 2. Durable-run event store and verification

`northstar-durable-run` generalises the audit surface for long-lived runs:
an append-only `event_store` with checkpoints and leases, a per-call
`action_gateway`, and an independent `verifier` that checks postconditions
after the fact rather than trusting the runner's own report. `trace_metrics`
keeps minimal span/trace numbers, and `evaluation` measures how closely a
recorded run followed the declared plan.

The lease vocabulary is shared with the runtime, and the enforcement is
deliberately not: durable-run's lease is reclaimed once `expires_at` passes,
because its runs outlive requests, while the runtime's is held by a live
descriptor and cannot be taken from a process that forgot to renew. Both write
the same two-field envelope (`owner_id`, `expires_at`) at mode `0600`, and a
checkpoint crosses the boundary as a valid `EventContract` event
(`checkpoint.created`) or a `northstar.checkpoint.v1` document via
`durable_bridge.py` — translated, never imported: the runtime does not depend
on this component, and the tests pin both sides of the mirror.

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
no signing, no retention policy, no tamper evidence (stated in the runtime
README's limitations). The roadmap's P3-1 is delivered in two batches: the
audit feed above (`audit.ndjson/1`, this batch) and policy schema-isation
(`northstar-policy.toml` versioning, next batch).

## Reading on

- Runtime: [Sessions, compaction, tracing](../../components/northstar-agent-runtime/README.md#sessions-compaction-tracing)
  and `sessions.py` / `session_view.py` in
  [docs/api/northstar-agent-runtime.md](../api/northstar-agent-runtime.md).
- Durable-run README: [Local example](../../components/northstar-durable-run/README.md#local-example)
  walks the event-store flow; API reference in
  [docs/api/northstar-durable-run.md](../api/northstar-durable-run.md).
- Contract: [docs/api/northstar-run-contract.md](../api/northstar-run-contract.md)
  and the [handoff-and-contracts](handoff-and-contracts.md) concept page.
