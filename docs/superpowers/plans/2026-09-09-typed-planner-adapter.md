# Typed Planner Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `test-driven-development` task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a provider-neutral planner boundary that converts bounded model output into an admitted `AgentPlan` candidate without granting the model direct tool execution authority.

**Architecture:** The adapter accepts a user goal and a host-owned model caller. The model caller returns untrusted JSON text or a JSON-compatible value. The adapter strictly parses a planner envelope, bounds retries and output size, rejects callable/command-like fields, and delegates final identity, scope, action, policy, and deadline checks to the existing `AgentLoop.admit`. No model call can execute an action.

**Tech Stack:** Python 3.12 standard library (`dataclasses`, `json`, `time`, `typing`, `unittest`); existing `AgentPlan` and `AgentLoop`; no network or credentials in tests.

## Global Constraints

- Modify only `/var/minis/workspace/northstar-agent-os-local-only`.
- Public checkout, integration, arena refs, research worktree, remotes, and servers remain frozen.
- Planner output is untrusted data and never receives a callable, shell command, credential, or direct action authority.
- Preserve existing `AgentPlan` and `AgentLoop` compatibility.
- Bound model output bytes, retry count, and model-call attempts.
- Record only bounded planner metadata and digests; never persist raw prompt or raw model output.
- Final success requires existing `AgentLoop.admit`; parsing alone is not authorization.

## Files

- Create: `components/northstar-durable-run/planner_adapter.py` — strict planner request/result contracts and bounded adapter.
- Create: `components/northstar-durable-run/tests/test_planner_adapter.py` — TDD coverage for parsing, bounds, repair, rejection, and admission delegation.
- Modify: `components/northstar-durable-run/README.md` — document planner boundary and local-only ceiling.
- Create: `docs/superpowers/plans/2026-09-09-typed-planner-adapter.md` — this plan and execution evidence.

### Task 1: Strict planner envelope

- [x] Write RED tests for missing/unknown fields, invalid JSON, oversized output, callable-like fields, and deterministic digest.
- [x] Run the focused tests and confirm failure is due to the missing adapter.
- [x] Implement `PlannerCandidate.from_value` with strict envelope fields: `schema_version`, `plan`, `model_id`, `provider`, `model_revision`, and `output_digest`.
- [x] Run focused tests and confirm GREEN.

### Task 2: Bounded model caller and schema repair

- [x] Write RED tests proving one valid call succeeds, malformed output gets at most one repair call, repeated malformed output fails closed, and no action executes during planning.
- [x] Implement `TypedPlannerAdapter.generate(goal, context, ...)` with a host-owned callable, bounded output bytes, one optional repair attempt, and `PlannerResult` containing only candidate digest/metadata.
- [x] Run focused tests and confirm GREEN.

### Task 3: Admission delegation and security boundaries

- [x] Write RED tests proving the adapter delegates the parsed `AgentPlan` to `AgentLoop.admit`, propagates policy/identity/scope rejection, rejects model output containing command/callable fields, and does not invoke registered actions.
- [x] Implement strict forbidden-key traversal and admission delegation without duplicating or weakening `AgentLoop` checks.
- [x] Run focused tests and confirm GREEN.

### Task 4: Documentation and verification

- [x] Document that the adapter is provider-neutral but still requires a host-owned model caller; it is not a model SDK or production planner service.
- [ ] Run planner tests, Durable Run tests, Interop tests, Host tests, Run Contract tests, documentation tests, py_compile, diff check, and sensitive scan.
- [ ] Confirm public checkout is unchanged.
- [ ] Create one local-only commit; never push.

## Proposed interfaces

```python
@dataclass(frozen=True)
class PlannerResult:
    candidate: AgentPlan
    candidate_digest: str
    model_id: str
    provider: str
    model_revision: str
    attempts: int

class TypedPlannerAdapter:
    def __init__(self, model_caller: Callable[..., Any], *, max_output_bytes: int = 256_000, max_attempts: int = 2): ...
    def generate(self, goal: str, *, context: dict[str, Any], loop: AgentLoop, current_policy_revision: str, owner_id: str, now: int) -> PlannerResult: ...
```

The adapter may ask the caller for a repair attempt, but it never executes `loop.actions`; only the caller of `AgentLoop.run` executes an admitted plan.
