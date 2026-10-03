# Northstar Durable Run Slice

This component is a local, standard-library prototype for the durable-run
mechanisms required by a governed Agent Runtime. It is deliberately narrow:
it proves contracts, event history, checkpoints, leases, per-call action gates,
independent postcondition verification, and minimal trace metrics on a local
fixture.

## Concepts, guides and API reference

- Concepts: [audit trail: sessions and durable history](../../docs/concepts/audit-trail.md) ·
  [governance and the permission gate](../../docs/concepts/governance.md)
- Guides: [packaging and CI](../../docs/guides/packaging-and-ci.md)
- API reference: [generated from docstrings](../../docs/api/northstar-durable-run.md)

## Install (pip)

```sh
pip install ../northstar-run-contract ../northstar-host   # declared dependencies
pip install .                                              # resolves both
```

The wheel installs the slice modules (`durable_contract`, `event_store`,
`action_gateway`, `runner`, `verifier`, `trace_metrics`, `evaluation`) as
top-level modules; the version (`0.1.0.dev0`, unreleased) is declared in
`pyproject.toml`.

## Boundaries

The component separates these stages:

```text
Run/Step contract
  → append-only event history
  → lease and runner lifecycle
  → per-call authorization/approval
  → bounded local step execution
  → independent postcondition verification
  → final receipt and trace metrics
```

The model is not an authority. A model-produced ToolCall is only a proposal;
`ActionGateway` requires a verified authorization grant and, for high-risk
tools, a matching human approval before invoking a registered executor. Tool
output cannot alter the registry, grant, or scope.

`EventStore` treats the JSONL history as the source of truth. Checkpoints carry
a state digest and sequence and are accepted only when they match the current
history. `DurableRunner` uses an owner-bound expiring lease with fencing
tokens, plus stable action keys, so a resumed fixture can avoid repeating an
idempotent side effect.
An expired lease is reclaimable by a new owner (crash recovery); an active
lease held by someone else still refuses. Every successful acquire starts a
new fencing epoch with a monotonically increasing token, and every heartbeat
and event append must present the current token: a holder whose lease was
taken over gets its writes refused (`FencingError`) instead of interleaving a
dead epoch's events with the new holder's stream, and the takeover is recorded
as a state-neutral `run.fenced` marker by the new holder. `DurableRunner`
accepts an optional `clock` (epoch seconds) to heartbeat the lease before
each step, and an optional `heartbeat_interval_seconds` (shorter than the
TTL, requires the clock) to renew the lease from a background thread *while*
a single step action executes — without it, a run that outlasts the TTL loses
its lease mid-execution, and a stolen lease raises instead of executing steps
unowned.

`verifier.py` does not trust a step's claimed output or a model's claimed
status. It checks the actual run state, private workspace, required file
 digests, and an observed test exit code. Only a `verified` result can produce
an `ok` receipt; missing observations produce `unknown` and failed checks
produce `failed`.

## Local example

The tests demonstrate a complete local flow:

```text
RunContract
  → EventStore + DurableRunner
  → ToolCall + ActionGateway
  → fixture workspace
  → independent verifier
  → durable receipt + trace span
```

Run the component tests from the repository root:

```sh
PYTHONPATH=components/northstar-durable-run \
  python3 -m unittest discover \
  -s components/northstar-durable-run/tests -p 'test_*.py' -v
```

## Deliberate ceiling

This is not a production scheduler, sandbox, VM, container runtime, browser
profile manager, distributed queue, or complete Agent OS. The first prototype
uses local JSONL and JSON files, caller-registered Python functions, and a
single-process test harness. It does not prove atomic claims across hosts,
network isolation, process isolation, native Linux
signal behavior, secret rotation, or production deployment safety.
The lease read-modify-write (`acquire`/`heartbeat`/`renew`/`release`) is
serialized with an `flock` on a `<lease>.lock` sidecar file that is never
renamed or deleted, so cooperating processes on the same POSIX host produce
exactly one claim winner and the fencing token increments exactly once per
acquire; a crashed holder's lock is released by the kernel, and writes still
go through temp-file + fsync + atomic rename, so no half-written lease is
left behind. Where `fcntl` is unavailable (non-POSIX) the claim degrades
honestly to thread-serial — `LeaseManager.cross_process_serialized` reports
the guarantee instead of pretending, and cross-process atomicity there is
unproven. The fencing tokens are enforced on every append and heartbeat,
but the token check and the following append are still a check-then-write,
not an atomic pair. Treat the lock as cooperative single-host arbitration
and the tokens as a single-writer discipline with loud detection, not as a
proven distributed lock.

Event history is exportable into the repository's canonical NDJSON audit feed
(`durable_audit.py`, envelope `audit.ndjson/1` from the run contract), so the
prototype's store can be shipped to a SIEM pipeline without changing format
later; see the [audit trail concept](../../docs/concepts/audit-trail.md).

Before any production integration, add native Linux/VM/container canaries,
crash and replay tests across process boundaries, durable queue semantics,
stronger filesystem and lease locking, cancellation propagation, tool-specific
postconditions, redacted audit export, and a fixed task-level benchmark. No
part of this component has been deployed to 103, 104, a dormitory host, or
production OpenBot.
