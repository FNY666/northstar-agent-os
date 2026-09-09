# Governed Autonomous Agent Loop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `test-driven-development` task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Add a local-only governed Agent Loop that admits typed planner output, executes registered actions, independently reads postconditions, checkpoints verified progress, and resumes without retrying an uncertain external side effect blindly.

**Architecture:** Keep `DurableRunner` and its existing event contract backward-compatible. Add `agent_loop.py` as a separate orchestration layer with a strict `AgentPlan`/`PlanStep` contract and an append-only, hash-chained loop evidence log. Planner output is untrusted data: admission binds it to the current `RunContract`, policy revision, registered action IDs, capability scope and deadlines before execution. Every action attempt gets a distinct `attempt_id` under one logical `execution_id`; the loop records only bounded digests/statuses. A host-owned postcondition observer performs an independent read-back before a step is considered committed. `unknown` pauses and checkpoints; only an independently observed `absent` result can authorize another attempt.

**Tech Stack:** Python 3.12 stdlib (`dataclasses`, `hashlib`, `json`, `fcntl`, `os`, `tempfile`, `pathlib`, `unittest`); existing `RunContract`; no network, real models, vendor CLIs, credentials, or remote writes.

## Global Constraints

- Modify only `/var/minis/workspace/northstar-agent-os-local-only`.
- Public checkout, `integration`, `arena/*`, research-route-journal, remotes and servers remain frozen.
- Do not copy or cherry-pick research-line source.
- Existing Durable Run, Interop, graph and evidence-store APIs remain compatible.
- Planner data, action outputs and observer details are untrusted/bounded; never persist prompts, secrets, raw errors or full tool output.
- A successful action return is not a verified postcondition; the observer is the only source of committed state.
- `unknown`/`unresolved` never becomes success and never directly authorizes retry.
- `execution_id` is the logical step identity; `attempt_id` is unique per execution attempt.
- Any malformed plan, loop event, hash chain, checkpoint, identity, scope, deadline or state transition fails closed.

## Public Interfaces

```python
@dataclass(frozen=True)
class PlanStep:
    step_id: str
    action_id: str
    input_payload: dict[str, Any]
    scope_snapshot: tuple[str, ...]
    expected_postconditions: tuple[str, ...]
    idempotency_key: str
    max_attempts: int

@dataclass(frozen=True)
class AgentPlan:
    schema_version: str
    plan_id: str
    plan_version: int
    task_id: str
    thread_id: str
    run_id: str
    actor_id: str
    workspace_id: str
    policy_revision: str
    trace_id: str
    steps: tuple[PlanStep, ...]
    plan_digest: str

@dataclass(frozen=True)
class PostconditionResult:
    verdict: str  # verified | absent | unknown
    reason_code: str
    observed_digest: str | None = None

@dataclass(frozen=True)
class LoopState:
    status: str  # admitted | running | paused_unknown | finished | failed
    plan_digest: str
    current_step_id: str | None
    steps: dict[str, dict[str, Any]]
    sequence: int

class AgentLoop:
    def __init__(self, run: RunContract, evidence_path: str | Path, *, actions: dict[str, Callable], observer: Callable): ...
    def admit(self, planner_output: AgentPlan | dict[str, Any], *, current_policy_revision: str) -> AgentPlan: ...
    def run(self, plan: AgentPlan, *, owner_id: str, now: int, current_policy_revision: str) -> LoopState: ...
    def resume(self, plan: AgentPlan, *, owner_id: str, now: int, current_policy_revision: str) -> LoopState: ...
    def state(self, plan_digest: str) -> LoopState: ...
```

The action registry is host-owned and keyed by bounded `action_id`; planner output cannot supply a callable or arbitrary command. The observer is host-owned and must independently inspect external state for the requested step/postconditions. It receives `(PlanStep, attempt_id)` and returns `PostconditionResult`.

## File Structure

- Create: `components/northstar-durable-run/agent_loop.py` — strict plan contracts, loop evidence records, atomic checkpointing, admission, execute/read-back/resume state machine.
- Create: `components/northstar-durable-run/tests/test_agent_loop.py` — TDD coverage for admission, verification, uncertainty, retry, crash recovery, idempotency and security boundaries.
- Modify: `components/northstar-durable-run/README.md` — document the governed loop and its non-production ceiling.
- Create/modify: `docs/superpowers/plans/2026-09-09-governed-agent-loop.md` — execution evidence and checked tasks.

### Task 1: Strict planner output and plan admission

- [x] Write RED tests proving missing module/contract fails, unknown action IDs are rejected, planner scope cannot exceed the run scope, identity/policy/deadline mismatches fail closed, and plan digest is deterministic.
- [x] Run focused tests and confirm the failure is due to the missing Agent Loop contract.
- [x] Implement bounded `PlanStep`/`AgentPlan` parsing, canonical digest and admission; no action executes during admission.
- [x] Run focused admission tests and confirm GREEN.

### Task 2: Attempt evidence, independent postcondition verification and checkpoint

- [x] Write RED tests for `attempted → verified`, action-return success not being sufficient, verified absence retry, and unknown postcondition pausing without retry.
- [x] Implement hash-chained loop events and atomic checkpoint/state replay. Persist only digests, IDs, statuses, attempt numbers and bounded reason codes.
- [x] Run focused execution tests and confirm GREEN.

### Task 3: Restart recovery and uncertain-side-effect rule

- [x] Write RED tests where an action mutates external fixture state then raises, a new loop instance resumes, and the observer verifies the state without a duplicate action; also test unknown read-back followed by resume.
- [x] Implement `execution_id`/`attempt_id` separation, observer-first resume for any incomplete/unknown attempt, idempotency conflict rejection, and terminal-state protection.
- [x] Run focused recovery tests and confirm GREEN.

### Task 4: Full local verification and local-only commit

- [x] Document that this is a local governed-loop prototype, not a real model loop, scheduler, sandbox, distributed broker or proof of exactly-once external side effects.
- [x] Run focused Agent Loop tests, all Durable Run tests, all Interop tests, py_compile, documentation tests, diff check and sensitive scan.
- [x] Confirm public checkout and arena refs are unchanged.
- [ ] Create one local-only commit after fresh verification; never push.

## Required state semantics

```text
admitted
→ running
→ attempted
→ verified_committed
→ running (next step)
→ finished

attempted/committed-unknown
→ observer verified      → verified_committed
→ observer absent        → retry only if attempt < max_attempts
→ observer unknown       → paused_unknown; no action retry
```

A process crash after the action call but before the observer is represented as an incomplete attempt. On restart the loop must read the postcondition first. It must not infer absence from a missing return value, lease expiry, exception, or process death.

## Known ceilings

- Actions and observers are caller-registered local Python functions; no real LLM planner or vendor backend is invoked.
- The evidence log proves the local loop's recorded transitions, not the external world. Postcondition verification quality depends on the independent observer.
- File-level atomic replace and flock are not distributed fencing; a real multi-host scheduler still needs leases, fencing tokens, external state read-back and deployment-specific tests.
