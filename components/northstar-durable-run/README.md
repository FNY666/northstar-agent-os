# Northstar Durable Run Slice

This component is a local, standard-library prototype for the durable-run
mechanisms required by a governed Agent Runtime. It is deliberately narrow:
it proves Run/Step/Event contracts, append-only event history, checkpoints,
leases, long-task lifecycle controls, per-call action gates, independent
postcondition verification, and minimal trace metrics on a local fixture.

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

The wheel installs the slice modules (`durable_contract`, `event_store`, `action_gateway`,
`cli`, `control_receipt`, `runner`, `verifier`, `trace_metrics`, `evaluation`,
`durable_transport`) as top-level modules; the version (`0.1.0.dev0`, unreleased)
is declared in `pyproject.toml`.

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
history. Event append and lease mutation use POSIX advisory lock sidecars so
same-run local processes serialize idempotent writes. `DurableRunner` uses an
owner-bound expiring execution lease and attempt-specific action keys so a
resumed fixture can avoid repeating an idempotent side effect.

## Long-task lifecycle

The runner exposes explicit durable control-plane transitions in addition to
`execute()`:

| Operation | Durable events | Result |
|---|---|---|
| `pause()` | `run.waiting` | `running → waiting` |
| `resume()` | `run.started` | `waiting → running` |
| `retry()` after failure | `run.retry`, then one `step.retry` per failed step | `failed → planned`, failed steps become `planned` |
| `cancel()` | `step.cancelled` for every active step, then `run.cancelled` | active work is recorded before terminal run cancellation |

`execute()` refuses a paused (`waiting`) run until `resume()` has appended its
new `run.started` event. Pause is a durable scheduling boundary, not a Python
thread interrupter: an action already inside a caller-registered function is
not forcibly stopped. If it later completes after cancellation, the runner
will not append a misleading `step.finished` event for the already-cancelled
step.

Each step attempt has a stable idempotency key passed to the action:
`<run_id>:<step_id>:attempt-1`, `attempt-2`, and so on. A process crash that
leaves `step.started` as the last step event does not create a retry event, so
recovery reuses the unfinished attempt key. An explicit `step.retry` event
advances the attempt and therefore receives a new key. The same distinction is
used for the durable `step.started`, `step.finished`, failure, checkpoint, and
run-start lifecycle event keys.

These controls preserve the existing lease, checkpoint, replay, verifier, and
append-only boundaries. They do not yet provide a background scheduler,
process-isolated signal cancellation, a cross-process task queue, or hosted
Profile B execution transport; the loopback control/replay slice is documented
below.

## Local control CLI

Installing the component also provides the `northstar-durable-run` command. It
is a local inspection/control surface, not a scheduler or network service; the
separate T21 `durable_transport.py` module is the explicitly loopback-only
network-shaped slice documented below. The read-only commands replay the same
validated EventStore history used by the runner:

```sh
northstar-durable-run status --events /path/run/events.jsonl --run-id run-001
northstar-durable-run history --events /path/run/events.jsonl --run-id run-001
northstar-durable-run audit --events /path/run/events.jsonl --run-id run-001
northstar-durable-run verify-receipt \
  --events /path/run/events.jsonl --receipt /path/run/pause.receipt.json
```

`verify-receipt` validates the receipt schema, exact event references, historical
before/after statuses, and the state digest by replaying the event prefix. It
can verify an older receipt after later events have been appended; failure is
reported without modifying the stream.

An operator can apply the local lifecycle controls by supplying the original
RunContract JSON and an owner identity. Each mutation is fenced by the same
owner-bound expiring lease as execution: an active lease held by another owner
is rejected rather than overwritten. Each command returns a versioned control
receipt containing the actor, command ID, before/after sequence, and exact
event IDs; an event-producing transition is `applied`, while a terminal repeat
or already-waiting control is `noop`. The EventStore remains the source of
truth. The command never executes a step or queues a retry:

```sh
northstar-durable-run control \
  --events /path/run/events.jsonl \
  --run-contract /path/run/run.json \
  --owner-id operator-1 --command-id hold-001 --now 1700000000 \
  pause --reason "manual hold"

northstar-durable-run control \
  --events /path/run/events.jsonl \
  --run-contract /path/run/run.json \
  --owner-id operator-1 --now 1700000001 resume
```

`--command-id` is optional for this local projection; provide it when an
upstream operator or API already has a stable command identity. Receipt IDs
remain per-response identifiers, and receipts are not a persisted command
ledger or an idempotency mechanism. `retry()` remains programmatic because a
retry must provide the explicit `StepPlan` actions and preserve the action
idempotency boundary. A future
scheduler may call this surface, but this component does not create one.

## Authenticated loopback transport (T21)

`durable_transport.py` provides a deliberately narrow network-shaped surface:
`DurableWorkerServer` and `DurableWorkerClient` exchange one bounded JSON line
per TCP connection for `status`, `history`, `pause`, `resume` and `cancel`.
Every frame has a channel HMAC, and every request carries the host-issued
binding and authorization tokens. The server checks run identity, opaque
workspace identity, policy revision, scope containment, capability
(`durable:read` or `durable:control`) and the run deadline before touching the
existing `EventStore`/`DurableRunner`.

The listener is loopback-only (`127.0.0.1`/`::1`) and does not accept a step
function, arbitrary path or serialized executor. `pause`/`resume`/`cancel`
return the existing versioned `ControlReceipt`; `history` is a bounded replay
of the authoritative event stream. This is a local control/replay transport
slice, not a remote worker service: it has no TLS/mTLS, workspace materialiser,
step execution protocol, scheduler, fleet lease service or public listener.
Use the existing SSH Profile A helper for the private sidecar socket path;
do not expose this server to a network without a separate deployment review.

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
small local test harness. POSIX advisory locks serialize the event/lease files,
but this does not prove atomic multi-process action claims, network isolation,
process isolation, lease fencing across hosts, native Linux signal behavior,
secret rotation, or production deployment safety.

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
