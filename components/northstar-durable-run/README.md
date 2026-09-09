# Northstar Durable Run Slice

This component is a local, standard-library prototype for the durable-run
mechanisms required by a governed Agent Runtime. It is deliberately narrow:
it proves contracts, event history, checkpoints, leases, per-call action gates,
independent postcondition verification, and minimal trace metrics on a local
fixture.

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
history. `DurableRunner` uses an owner-bound expiring lease and stable action
keys so a resumed fixture can avoid repeating an idempotent side effect.

`verifier.py` does not trust a step's claimed output or a model's claimed
status. It checks the actual run state, private workspace, required file
 digests, and an observed test exit code. Only a `verified` result can produce
an `ok` receipt; missing observations produce `unknown` and failed checks
produce `failed`.

The provider-neutral `planner_adapter.py` adds the next boundary above the
loop: a host-owned model caller may return only a bounded planner candidate.
The adapter rejects command/callable/credential-like fields, permits at most one
repair attempt by default, and sends the parsed `AgentPlan` through the existing
admission checks. It never executes an action during planning. This is still an
adapter boundary, not a bundled model SDK or production planner service.

strict planner-produced `AgentPlan`, persists a bounded plan-step manifest in
the first admission event, executes only registered actions, and requires an
independent observer read-back. A manifest binds every evidence `step_id`,
logical `execution_id`, and per-attempt `attempt_id` to the admitted plan;
forged or unplanned identities fail closed before evidence is written. An
`unknown` read-back pauses the loop, while only an independently observed
`absent` result can authorize a bounded retry. This remains a local-only
prototype, not a real model planner or proof of exactly-once external effects.


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
single-process test harness. It does not prove atomic multi-process claims,
network isolation, process isolation, lease fencing under races, native Linux
signal behavior, secret rotation, or production deployment safety.

Before any production integration, add native Linux/VM/container canaries,
crash and replay tests across process boundaries, durable queue semantics,
stronger filesystem and lease locking, cancellation propagation, tool-specific
postconditions, redacted audit export, and a fixed task-level benchmark. No
part of this component has been deployed to 103, 104, a dormitory host, or
production OpenBot.
