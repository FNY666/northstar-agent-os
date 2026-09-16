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

`completion_contract_v2.py` is a test-only completion contract derived from
stateful-agent benchmark research. It is deliberately not wired into
`TaskOutcome.ok` yet. It combines host-owned artifact expectations, an
independent before/after workspace snapshot, an allowed mutation set, optional
ordered milestones, and a versioned provenance envelope containing evaluator,
fixture, benchmark commit, environment, model, reasoning, budget, seed, and
trial identity. It returns `verified`, `failed`, `unknown`, or
`insufficient_information` and never treats a model claim or tool receipt as
proof. Exact digests cover binary artifacts; structured semantic fields allow
controlled formatting variation while rejecting missing fields, explicit
negation, wrong values, and duplicate conflicting fields. The accompanying
unit tests and archive audit are the gate before any production verifier
change.

```sh
PYTHONPATH=components/northstar-durable-run:components/northstar-run-contract:components/northstar-host \
  python3 -m unittest components.northstar-durable-run.tests.test_completion_contract_v2
```

The first archive audit accepted all three historical correct artifacts and
rejected all three semantic-negation cases plus all three collateral-file cases.
`completion_replay.py` then adapts a real Northstar `report.json` plus an
independently checked evidence JSONL into the test-only contract: the archived
report without provenance returns `insufficient_information`, while an
explicitly enriched host-owned provenance envelope plus a valid terminal
`loop.finished` evidence chain verifies. The adapter ignores report `ok` and
verification claims. `ReplayConfig` can generate the provenance envelope from
host-selected evaluator/fixture files plus benchmark commit, environment,
model, reasoning, budget, seed, and trial inputs; report-supplied provenance
is only a fallback for compatibility and is still checked against the contract.
This is evidence for the test evaluator only; it does not establish general
semantic truth or authorize production rollout.

`completion_batch_replay.py` replays every archived run through that contract in
two independent passes. The `digest` pass requires each archived deliverable to
hash to a digest the run's final round actually committed in its evidence
journal, which binds the archive to the run rather than to the report; the
`semantic` pass requires host-declared fields parsed from the deliverable's own
content. Hard-coded declarations live in `replay/archive-replay-spec.json`, and
nothing in the replay reads report `ok` or `verification`.

```sh
PYTHONPATH=components/northstar-durable-run:components/northstar-run-contract:components/northstar-host \
  python3 components/northstar-durable-run/completion_batch_replay.py
```

Across the five archived tasks the `digest` pass verifies all five, so the
contract does not misjudge any archived legitimate completion. The `semantic`
pass verifies four and returns `insufficient_information` for the release note,
whose deliverable states its facts as prose and headings with no machine-
checkable key/value statements; failing closed there is the intended behaviour
rather than a false negative. Two provenance limits are reported instead of
hidden: the archived runs did not record their original `max_output_tokens`,
`reasoning_effort`, or model revision, so the envelope describes host-declared
replay conditions, and the release-note fixture's three requirements are not
expressible as declared semantic fields, which the spec records as a coverage
gap.

`completion_workspace_snapshot.py` removes the remaining hand-built input. The
contract needs independent before/after state, so this module observes a real
directory tree instead of trusting caller-supplied text. It mirrors the
agent-facing listing tool's posture — host-owned root, `O_NOFOLLOW` reads,
bounded depth and entry counts, no symlink following — and differs in one
deliberate way: it retains file content at or below the declared text bound so
semantic fields can be parsed, and reduces larger, non-UTF-8, or empty files to
a digest so absence and emptiness stay distinguishable. Observation is
fail-closed: a symlink, an unsupported entry kind, or a tree beyond the bounds
refuses the whole observation rather than yielding a partial snapshot that a
completion decision might trust.

```sh
PYTHONPATH=components/northstar-durable-run:components/northstar-run-contract:components/northstar-host \
  python3 components/northstar-durable-run/completion_batch_replay.py --observe
```

Replaying the archive with `--observe` materializes each archived workspace,
observes the real directory before and after the deliverable is written, and
reproduces the identical distribution — five verified in the `digest` pass and
four verified plus one `insufficient_information` in the `semantic` pass — so
the verdict does not depend on which snapshot source is used.

`completion_coverage.py` turns the release-note limitation into a measured
precondition. It reads each fixture's own asserted values, then checks whether
every one of them is bound by a declared semantic field, so a task whose
deliverable never states a required fact as a checkable key/value pair is
rejected while the task is being defined rather than surfacing as an
unverifiable completion later.

```sh
PYTHONPATH=components/northstar-durable-run:components/northstar-run-contract:components/northstar-host \
  python3 components/northstar-durable-run/completion_coverage.py --strict
```

Across the archive the audit binds 15 of 19 asserted requirements and marks
three of five tasks fully checkable. Strengthening one declaration to pin the
whole column list lifts `live-column-report-v2` from three of five to five of
five, so declaration quality is now measurable rather than assumed. The two
remaining gaps are genuine task-design defects, not verifier gaps: the first
live run states its row count in prose with no key, and the release note states
all three of its facts as prose and headings. `--strict` exits non-zero while
any requirement is unbound, which makes the audit usable as a gate on task
definitions.

`completion_replay.py` also verifies the evidence journal's own integrity rather
than only parsing it. Archived journals are hash-chained — each event carries a
`sequence`, an `event_digest`, and the `prev_event_digest` it extends — and the
replay now recomputes each digest and checks both the chain link and the
sequence before trusting a terminal `loop.finished`. Sequence continuity alone
would miss an event rewritten in place and renumbered, which the digest
comparison catches; an inserted duplicate is caught even when the attacker
renumbers the rest.

Two boundaries are pinned by tests rather than left implicit. A process killed
mid-append leaves unparseable bytes, which is a different failure from a
cleanly shortened journal, and dropping the final event leaves a shorter chain
that is still internally consistent — so a missing tail is detected by the
terminal-state check, not by the chain. An actor who rewrites the whole file and
recomputes the entire chain produces an internally consistent journal, so
integrity checking cannot prove the contents were never rewritten; that needs an
anchor held outside the journal. All ten archived journals verify intact, so the
added checking produces no false rejections on the real corpus.

`tests/test_completion_trust_boundary.py` pins the assumption the whole contract
rests on: that the evidence journal sits outside the actor's write domain. The
run layout puts `workspace/` and `evidence/` side by side, so the boundary is
only real if no agent-reachable call can cross between them. The checks cover
parent-traversal, absolute paths, and symlink escapes through both the write and
list tools, including a symlink planted one level down, and assert the journal's
digest is byte-identical afterwards. The production wiring was traced rather
than assumed: `agent_entry.py` registers tools whose executors delegate to the
path-safe `WorkspaceWriteTool` rather than writing to disk directly. Gateway
identity, resource, capability, and arguments-digest binding is already covered
by `test_action_gateway.py` and is not duplicated here.

`tests/test_completion_guarantee_scope.py` guards that boundary against future
weakening by driving the real production harness — the tools `agent_entry.py`
actually registers — and attempting escapes through them, including a symlink
planted inside the workspace and a write aimed at the journal itself. A positive
control runs a legitimate write first and proves the step really reaches the
executor, so a boundary assertion cannot pass merely because nothing ran.

That control exists for a reason: the first version of these checks passed even
after the registered executor was replaced with a direct write that skipped the
path guard. Their assertions held trivially because the step never executed at
all. Mutation testing caught it, and the three root causes were a wrong
postcondition name, a wrongly wrapped planner candidate, and a pre-seeded
journal the harness rejected as an invalid event. With those fixed, replacing
the executor with a direct write fails three of the five checks while the
control and the read check still pass, which is what makes the guards evidence
rather than decoration.

`mutation_check.py` makes that verification repeatable instead of a one-off. It
declares four weakenings — the registered executor bypassing the path guard, the
write tool accepting parent traversal, the observer skipping symlinks instead of
refusing them, and the replay skipping chain verification — plus one neutral
change. Each declaration is applied inside a scratch copy of the component, and
the named guard must then fail; the neutral change must leave the guards passing
so a harness that simply failed everything could not look correct; and a
baseline run first confirms the guards pass unmutated.

```sh
python3 components/northstar-durable-run/mutation_check.py
```

`tests/test_mutation_declarations.py` checks the same declarations cheaply on
every test pass, so a declaration that stops matching the code fails fast
instead of silently skipping its guard.

`tests/test_completion_gate_composition.py` settles how this contract relates to
the production gate. A live run writes two different artifacts: the durable
runner writes an event store consumed by `verify_run_completion`, and the agent
harness writes this hash-chained evidence journal. The event contract carries
`run_id`, `trace_id`, and `payload_digest`, none of which appear in the journal,
and the journal carries `event_digest`, `prev_event_digest`, and
`observed_digest`, none of which appear in the event contract, so neither gate
can be replayed from the other's artifact.

The consequence is tested in both directions rather than asserted. The contract
returns `verified` for a finished run whose test exit code is non-zero, which
the production gate rejects, so replacing that gate with this contract would
drop the exit-code check. Conversely the production gate returns `verified` for a
deliverable whose digest matches even though the claim inside it is negated
(`Top scorer: carol, NOT verified by source`), which this contract rejects. The
two are therefore layered: production keeps the durable gate and adds this one
on top, rather than swapping one for the other.

One archival gap follows from the same finding: the archived runs preserved the
evidence journal but not the durable event store, so the production gate cannot
be replayed over the archive and only this contract's half of the comparison can
be re-run today.

`completion_shadow.py` is the first safe integration surface for the layered
decision. It takes a production `VerificationResult` and a contract
`CompletionResult`, preserves both underlying verdicts and namespaced errors,
and returns `verified` only when both are verified. Any failure dominates;
unknown and insufficient-information states remain fail-closed. Crucially,
`execution_authorized` is invariantly false: this is a shadow comparison policy,
not a change to `TaskOutcome.ok` or a new authorization path. The policy tests
pin the composition matrix before any production wiring is considered.

`completion_live_shadow.py` drives that policy against a real `AgentHarness` run
in test-only code. It observes the host workspace before and after the run, uses
the harness-owned verification as the production-side result, independently
validates the evidence journal, and passes both results to `completion_shadow.py`.
The adapter preserves the original `TaskOutcome` unchanged; missing evidence or
a non-finished run cannot be promoted by a successful artifact check, and the
layered result remains non-authorizing. The live tests include a positive real
write, a missing-evidence case, and a non-finished task-state case.

`live_shadow_run.py` turns the same process into a repeatable real-model run:
a host-owned fixture declares the production contains check, the contract's
machine-checkable semantic fields, and the action-id-to-milestone mapping. It
creates a fresh private sandbox, calls the configured OpenAI-compatible planner,
and writes a report containing the original task outcome, both gate verdicts,
the non-authorizing layered verdict, and digest-only before/after views. The
first low-cost live run used DeepSeek V4 Flash with `reasoning=off` and a 1024
token cap; it completed `workspace.list → repo.read → workspace.write`, and all
three verdicts were `verified` while `execution_authorized` remained false. Its
fixture is covered by offline tests so the semantic contract and negative
semantic case remain reproducible without making another provider call.

The real shadow corpus currently covers four distinct conditions: a normal
completion and a host-injected transient write failure that recovered on its
second attempt both yielded `production=verified`, `contract=verified`, and
`layered=verified`; a deliberately negated semantic claim and a real extra
`out/notes.txt` collateral write both yielded `production=verified` but
`contract=failed` and `layered=failed`. Each run is isolated under
`shared/northstar-live-shadow/`, records its evidence journal, and is scanned
for credentials. This is a small sample, not a production rollout statistic,
but it establishes that the layered gate distinguishes recovery from semantic
and collateral violations on real model output.

`completion_advisory.py` carries the same comparison into the ordinary
production run. When a fixture declares a `shadow_contract`, `live_run.py`
attaches a `shadow_advisory` object to its report and nothing else changes: the
production gate alone still decides `ok` and the exit code, and a fixture
without a shadow contract produces a report with no advisory field at all. The
advisory records `authoritative`, `affects_task_outcome`, and
`execution_authorized` as false, carries a digest over its own payload so a
later edit is detectable, and records a reason instead of an opinion when the
workspace cannot be observed or the contract cannot be evaluated — including a
malformed fixture spec, which must degrade to a recorded `advisory_error:...`
rather than interrupt the run that actually decides success. The advisory binds
the *final* round's evidence journal, and a twin test proves that binding is
real: identical inputs with only the terminal journal removed change the
verdict. Three mutation declarations keep this honest: making the exit code read
the advisory, widening the contract's allowed mutations, or ignoring the
evidence journal must each make the guards fail.

`live/advisory-*.json` are the fixtures that turn the advisory on for the
ordinary production path; a fixture-integrity test keeps their production
expectations, contract artifacts, and milestone map from drifting apart. The
first live production run of this path (2026-09-16, DeepSeek V4 Flash) produced
a verified advisory, and a second run reproduced a failure worth keeping: the
provider refused the second round (HTTP 402, exhausted credit) after the first
round delivered a wrong report, and the advisory had to report `unknown` rather
than inherit that round's apparent progress. An offline guard now pins that
sequence.

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
