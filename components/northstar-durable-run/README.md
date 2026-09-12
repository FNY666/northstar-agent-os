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

`openai_compatible_planner.py` provides an optional standard-library caller for
an explicitly configured HTTPS OpenAI-compatible endpoint. Configure the
endpoint URL, API-key environment-variable name, model ID, provider, and model
revision in host code; the model response can supply only a `plan` object. The
caller does not retry transport failures and never logs the API-key value. Tests
use a fake transport; no live provider is configured in this repository.

`repo_read.py` is the first real read-only action bound to an admitted plan.
`RepoReadTool` owns its workspace root, walks every path component with
`O_NOFOLLOW`, rejects absolute paths, traversal, symlinked components,
directories, non-regular files, and payloads outside
`{"path", "max_bytes"}`, and enforces a byte bound plus a post-read stability
check. It never writes, and it is not an OS sandbox or a secret classifier:
anything readable inside the host-owned root is readable by this tool, so pair
it with `allowed_paths` and an independent observer.

Action failures are traceable, and refusals are distinct from errors. When a
registered action raises, the loop records `step.action_failed` with the
failure *kind* (`ValueError`, `CustomFailure`, ...) and never copies the
exception message into evidence, so a trace can distinguish "the action ran"
from "the action raised". Recovery through an independent observer remains
legal there, because a remotely committed effect may still be verifiable after
a local error.

When an action raises `ActionNotExecuted` instead, the loop records
`step.action_denied` and refuses to let observation stand in for the action: a
step that certainly never ran cannot become a verified commit merely because
the world already matches. Recovery re-dispatches it inside the attempt budget,
and an exhausted budget fails closed.

`governed_dispatch.py` routes loop actions through `ActionGateway`. The loop
stays unaware of the gateway; a host binds one dispatcher callable per action
id, and every attempt is re-authorized against a fresh `ToolCall` built from the
admitted plan (task, thread, run, step, actor, workspace, trace, scope,
arguments digest, deadline). Refusals surface as `GovernanceDenied` and unbound
steps as `UnboundAction` — both `ActionNotExecuted` subclasses, so they reach
evidence as denials rather than as tool crashes. Each attempt uses its own
idempotency key so a retry really executes instead of replaying a cached result.

Recovery keys off the derived `denied` flag on the step, not off the observation
reason code, so a refusal stays visible even when the observer reports its own
"unverified" reason. A repeated resume also records each pause attempt, so a run
cannot sit in `running` with no closing event.

A high-risk tool without approval is recorded as `step.awaiting_approval` and the
run rests in `awaiting_approval`. Waiting is a human time scale, so it does not
consume the step's attempt budget — the budget counts executions, and a wait is
never an execution; the step deadline is what bounds it. A refusal (expired
grant, missing capability, unregistered tool) still consumes the budget and
stays fail-closed.


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

`workspace_write.py` is the write counterpart of the bounded read: `WorkspaceWriteTool`
owns a host-owned root, accepts exactly `{"path", "content"}`, rejects absolute
paths, traversal, symlinked targets or intermediate directories, directories, and
sizes over the bound, then writes through an exclusive `0o600` temporary file that
is fsynced and renamed into place. A reader never observes a partial file, an
existing symlink is never replaced, and the result reports `created` plus the
previous digest. It is not an OS sandbox or a secret boundary: anything writable
inside the root is writable through it, so pair it with an allowlist, a private
root, and an independent observer. A tool that rejects its input surfaces as
`step.action_denied`, not as an execution error: the gateway refuses it before it
can touch the outside world.

`agent_entry.py` is the first entry point that runs a whole task. `AgentHarness`
binds one run, one workspace root, three real tools (`workspace.list`,
`repo.read`, and `workspace.write`), the authorization chain, and an
independent observer, then drives `goal → planner candidate → admission →
per-step authorization → bounded real tools → independent observation → bounded
autonomous resume → independent final check`. The observer re-reads the world
itself and never trusts the tool's output. `workspace.list` is metadata-only:
it returns bounded names, kinds, and file sizes, never content; content still
requires an explicit `repo.read` step. The list action and the read/write
actions all use the same per-call authorization chain. Postconditions are a
fixed vocabulary (`listing_ok`, `read_ok`, `file_present`,
`content_matches_payload`, `file_absent`) and an unknown postcondition is never
a verified one. `TaskOutcome.ok` requires both a `finished` loop and a
host-owned verification of the expected artifacts, so a finished run whose
deliverable is wrong is not a done task. Approvals, high-risk tools,
re-planning, and network tools are still absent; the harness also exposes
fault-injection hooks used only by tests and the benchmark.

`agent_benchmark.py` scores whole tasks instead of contracts. Each fixture
(`benchmarks/agent_tasks.json`) is a host-owned task definition with seed files,
steps, expected artifacts, and an optional injected fault; every task gets a
fresh workspace and evidence stream, so a result cannot depend on leftovers. It
reports task success rate, step-level verification, and recovery counts for
injected faults. The planner is a *scripted* fixture caller: this measures the
execution, recovery, and verification harness, not model planning quality.

```sh
PYTHONPATH=components/northstar-durable-run:components/northstar-run-contract:components/northstar-host \
  python3 components/northstar-durable-run/agent_benchmark.py
```

`agent_driver.py` closes the loop a static plan cannot close. A plan fixes
`content` before anything has been read, so a data-dependent deliverable is
impossible in one plan. The driver runs bounded rounds of
`plan → execute → observe → re-plan`: each round is its own governed run with
its own run id, authorization grant, and evidence file; observations are
collected by the host from the filesystem (never from a tool's claimed output);
and the model sees only bounded observations plus a bounded workspace
inventory. Only a round that provably produced no effect may be re-planned — a
refused action (`step.action_denied`) or a pending approval stops the driver,
and an uncertain (`paused_unknown`) round stops it too. The deliverable is still
verified by the host against host-owned expectations, so a confident model is
never the evidence.

`workspace.list` is the bounded exploration action used before a model knows
which file to read. Its payload is exactly `{"prefix", "max_depth",
"max_entries"}`. It returns sorted relative names, `file`/`directory` kinds,
file sizes, and a truncation flag; it never returns file content and never
follows or returns symlinks. The action still goes through the per-call gateway
and an independent host postcondition (`listing_ok`), so listing metadata does
not grant read or write authority. The driver stores a list observation under
`listing:<prefix>`; a subsequent `repo.read` is required to obtain content.

`live_run.py` is the single-task real-model path: it seeds a private workspace
from a fixture, drives the same chain with an OpenAI-compatible model, and
writes a report beside the evidence streams. `live/first_live_task.json` is the
first recorded task. The model receives the published planner context (identity,
budget, action schema, inventory, observations) and never a credential.

`live_benchmark.py` runs a directory of independent real-model fixtures and
reports task success rate, total rounds, model calls, recovery rounds, token
usage, provider-reported cost, and evidence-derived action-failure recovery.
Each task gets a fresh sandbox and evidence stream; a pre-existing benchmark
sandbox is refused. The checked-in fixtures under `live/tasks/` cover CSV column
extraction, changelog summarizing, numeric score auditing, and one bounded
transient `workspace.write` failure. Faults are host-owned evaluation controls,
not model capabilities; the benchmark counts `step.action_failed` in evidence
and requires final host verification before calling recovery successful. The
host-owned `contains` expectations are the only task success criterion.

```sh
OPENROUTER_API_KEY=... PYTHONPATH=components/northstar-durable-run:components/northstar-run-contract:components/northstar-host \
  python3 components/northstar-durable-run/live_benchmark.py \
  --tasks components/northstar-durable-run/live/tasks \
  --endpoint https://openrouter.ai/api/v1/chat/completions \
  --key-env OPENROUTER_API_KEY --model deepseek/deepseek-v4-flash --provider openrouter \
  --reasoning off --max-output-tokens 2048 \
  --sandbox /tmp/northstar-live-benchmark --report /tmp/northstar-live-benchmark/report.json
```

The current recorded live benchmark used DeepSeek V4 Flash through OpenRouter
with reasoning disabled and a 2048-token output ceiling: 3/3 tasks were
independently verified in 6 rounds and 6 model calls. Provider-reported usage
was 8,664 total tokens at cost `0.001083739986` (OpenRouter accounting; not a
price guarantee). A separate recovery fixture then injected one host-owned
`workspace.write` execution failure: evidence contained one
`step.action_failed`, the same round retried the write successfully, and the
host verified the final `out/recovery.md`; that run used 2 calls, 2,986 tokens,
and provider cost `0.0002801421`. This proves one bounded execution-failure
recovery path only; it does not prove arbitrary crash recovery, exactly-once
external side effects, or production reliability. The reports and evidence are
archived outside the repository under
`/var/minis/shared/northstar-live-runs/` when a run is retained.

Real-model findings worth keeping: gateways price a request by its worst case,
so the host must send an explicit `max_tokens` or the call is refused; reasoning
models spend that budget thinking before emitting the plan, so a ceiling sized
for the answer alone truncates the call; and a round must never reuse an
existing evidence file, or the loop rejects the new plan digest against the old
events.

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
postconditions, redacted audit export, and a real-model planner benchmark (the
task-level benchmark exists, but its planner is a scripted fixture, so nothing
here measures model planning quality yet). No part of this component has been
deployed to 103, 104, a dormitory host, or production OpenBot.
