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

## Honest ceiling

Transcripts and stores are a **local audit trail, not a compliance store**:
no signing, no retention policy, no tamper evidence (stated in the runtime
README's limitations). P3-1 on the DX benchmark roadmap (policy-as-code plus
audit export to NDJSON/SIEM) is the planned next step.

## Reading on

- Runtime: [Sessions, compaction, tracing](../../components/northstar-agent-runtime/README.md#sessions-compaction-tracing)
  and `sessions.py` / `session_view.py` in
  [docs/api/northstar-agent-runtime.md](../api/northstar-agent-runtime.md).
- Durable-run README: [Local example](../../components/northstar-durable-run/README.md#local-example)
  walks the event-store flow; API reference in
  [docs/api/northstar-durable-run.md](../api/northstar-durable-run.md).
- Contract: [docs/api/northstar-run-contract.md](../api/northstar-run-contract.md)
  and the [handoff-and-contracts](handoff-and-contracts.md) concept page.
