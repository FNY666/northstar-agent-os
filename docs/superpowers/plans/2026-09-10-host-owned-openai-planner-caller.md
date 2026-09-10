# Host-Owned OpenAI-Compatible Planner Caller Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `test-driven-development` task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a default-disabled, standard-library OpenAI-compatible planner caller whose provider/model metadata is host-owned rather than supplied by untrusted model JSON.

**Architecture:** `TypedPlannerAdapter` will accept a typed `PlannerModelResponse` from a host-owned caller, rather than a raw candidate envelope from model output. The OpenAI-compatible caller sends bounded JSON to a configured HTTPS endpoint, retrieves its key by environment-variable name without logging it, extracts one JSON response content string, and binds configured provider/model/revision metadata before returning it to the adapter. The adapter still parses, forbids dangerous fields, and calls `AgentLoop.admit`; no action execution occurs.

**Tech Stack:** Python 3.12 standard library (`dataclasses`, `json`, `os`, `urllib`, `unittest`); no SDK, network service, credential, or live model call in tests.

## Global Constraints

- Modify only `/var/minis/workspace/northstar-agent-os-local-only`.
- Public checkout, integration, arena refs, research worktree, remotes, and servers remain frozen.
- Never put an API key or credential value in source, test fixtures, logs, exceptions, traces, or commits.
- Model JSON may provide only a `{ "plan": ... }` body; provider/model/revision come from host configuration.
- HTTPS is required for endpoint configuration. No endpoint, model, header, tool, command, or credential comes from model output.
- The caller must not retry transport/provider failures. Existing adapter repair applies only to malformed planner output and is bounded to one repair attempt by default.
- Tests use fake transport only; they must not send a network request.

## Files

- Modify: `components/northstar-durable-run/planner_adapter.py` — add `PlannerModelResponse`; require host-owned typed model response during `TypedPlannerAdapter.generate`.
- Create: `components/northstar-durable-run/openai_compatible_planner.py` — HTTPS request construction, bounded response parsing, secret loading, and host metadata binding.
- Modify: `components/northstar-durable-run/tests/test_planner_adapter.py` — reject raw model dictionaries returned by callers.
- Create: `components/northstar-durable-run/tests/test_openai_compatible_planner.py` — fake-transport tests for requests, metadata binding, invalid responses, size limits, endpoint/secret boundaries.
- Modify: `components/northstar-durable-run/README.md` — configuration and non-live-test ceiling.

### Task 1: Host-owned model metadata

- [x] Write RED test showing `TypedPlannerAdapter` rejects a raw dictionary caller result and accepts only a typed host-owned `PlannerModelResponse`.
- [x] Run focused planner tests and confirm failure is due to the old raw result interface.
- [x] Implement `PlannerModelResponse` and change adapter parsing to accept only it; preserve `PlannerCandidate.from_value` as a standalone strict envelope parser.
- [x] Run focused planner tests and confirm GREEN.

### Task 2: OpenAI-compatible HTTP caller

- [x] Write RED fake-transport tests for HTTPS endpoint validation, host-owned `Authorization` header, strict request body, metadata binding, and plan-only model content.
- [x] Run focused tests and confirm the new module is missing.
- [x] Implement `OpenAICompatiblePlannerConfig` and `OpenAICompatiblePlannerCaller` using stdlib `urllib`; constrain endpoint, timeout, request/response size, and response path.
- [x] Run focused tests and confirm GREEN.

### Task 3: Fail-closed provider boundaries

- [x] Write RED tests for missing credential, HTTP/transport errors, oversized response, malformed provider response, and model attempt to return provider metadata.
- [x] Implement sanitized failures with no raw provider body or credential in error text; no transport retry.
- [x] Run focused tests and confirm GREEN.

### Task 4: Documentation and verification

- [x] Document required variable names without values: `NORTHSTAR_PLANNER_ENDPOINT`, `NORTHSTAR_PLANNER_API_KEY`, `NORTHSTAR_PLANNER_MODEL`, and configured provider/revision metadata.
- [x] Run Planner + Durable Run, Sidecar, Interop, Host, Run Contract, documentation tests, py_compile, diff check, and sensitive scan.
- [x] Confirm public checkout remains unchanged.
- [ ] Create one local-only commit; never push.

## Proposed interfaces

```python
@dataclass(frozen=True)
class PlannerModelResponse:
    content: str | dict[str, Any]  # exactly {"plan": AgentPlan-json}
    model_id: str                  # host-owned
    provider: str                  # host-owned
    model_revision: str            # host-owned

@dataclass(frozen=True)
class OpenAICompatiblePlannerConfig:
    endpoint: str                  # full HTTPS /chat/completions endpoint
    api_key_env: str
    model_id: str
    provider: str
    model_revision: str
    timeout_seconds: float = 30.0
    max_response_bytes: int = 262_144

class OpenAICompatiblePlannerCaller:
    def __call__(self, *, goal: str, context: dict[str, Any], repair_error: str | None, attempt: int) -> PlannerModelResponse: ...
```
