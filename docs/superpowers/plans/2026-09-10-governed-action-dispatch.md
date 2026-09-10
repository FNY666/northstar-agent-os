# Governed Action Dispatch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `test-driven-development` task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make AgentLoop actions pass the same ToolCall authorization chain as every other tool call, and make "refused" distinguishable from "errored" all the way through recovery.

**Architecture:** `GovernedActionDispatcher` bridges the loop's `(step, attempt_id)` action signature to `ActionGateway.execute`, building a full `ToolCall` from the admitted plan and host-owned credentials. The loop stays gateway-unaware. A new `ActionNotExecuted` contract class marks actions that certainly never ran; the loop records those as `step.action_denied` and refuses to let observer read-back substitute for execution, re-dispatching instead within the attempt budget.

**Tech Stack:** Python 3.12 standard library; existing durable-run, run-contract, interop, and host components. No network, credentials, or new dependencies.

## Global Constraints

- Modify only `/var/minis/workspace/northstar-agent-os-local-only`.
- Public checkout (`/var/minis/workspace/northstar-agent-os`), remotes, integration and arena refs remain frozen.
- Never place an API key, token, or credential value in source, test fixtures, logs, evidence, exceptions, or commits.
- Evidence must never carry exception messages — only failure kinds.
- A step that certainly never executed must never become `verified_committed` through observation alone.
- Committed-unknown recovery (ordinary action errors) must keep trusting an independent observer.

## Files

- Create: `components/northstar-durable-run/governed_dispatch.py` — `GovernedActionDispatcher`, `UnboundAction`, `GovernanceDenied`.
- Modify: `components/northstar-durable-run/agent_loop.py` — `ActionNotExecuted` contract, `step.action_denied` event, denial-aware recovery.
- Create: `components/northstar-durable-run/tests/test_governed_dispatch.py` — authorization, denial, and recovery tests.
- Modify: `components/northstar-durable-run/README.md` — dispatch and refusal semantics.

### Task 1: Authorization-bound dispatch

- [x] Write RED tests: authorized dispatch executes; missing step binding, capability beyond grant, tool scope not requested, expired grant, and unregistered tool all deny.
- [x] Implement `GovernedActionDispatcher` building a full `ToolCall` per attempt from the admitted plan.
- [x] Run focused tests and confirm GREEN (7 tests).

### Task 2: Refusal is not "unknown"

- [x] Forensic probe: a refused action plus a favourable world state produced `verified_committed` and `finished`.
- [x] Add `ActionNotExecuted` contract; deny path records `step.action_denied` and downgrades a verified observation to `unknown`.
- [x] Make `UnboundAction` / `GovernanceDenied` subclasses of the contract.
- [x] Run focused tests and confirm GREEN.

### Task 3: Recovery must re-dispatch, not observe

- [x] Write RED tests: recovery re-dispatches a refused attempt inside budget; an exhausted budget fails closed and never finishes on observation.
- [x] Skip the `observe_only` recovery path when the last observation was `action_not_executed`, falling through to the bounded dispatch loop.
- [x] Run focused tests and confirm GREEN (9 tests).

### Task 4: Verification and commit

- [x] Durable Run 108/108, Interop 136/136 (absolute PYTHONPATH), Host 24/24, Contract 22/22, Sidecar 51/51, Docs 3/3.
- [x] py_compile, `git diff --check`, sensitive scan.
- [x] Confirm public checkout unchanged.
- [x] Create one local-only commit; never push.

### Task 6: Waiting for approval is not a failed attempt

- [x] Write tests: a wait does not consume the attempt budget; repeated waits keep it intact; the wait is visible as `step.awaiting_approval`; a wait past the step deadline fails closed; a genuine refusal still consumes the budget.
- [x] Add the `ActionAwaitingApproval` contract and `ApprovalPending`; the dispatcher consults the registered tool's risk level before dispatch, so a missing approval is a wait rather than a gateway refusal.
- [x] Fix: the `step.attempted` handler rebuilt the step dict and dropped accumulated `waits`/`denied`, resetting the budget arithmetic every round (forensic probe showed round 2 as `waits=1`, round 3 as `max_attempts_exhausted`). Accumulated fields now survive a new attempt.
- [x] Budget counts executions (`attempt - waits`), and recovery from `awaiting_approval` re-dispatches without spending it.
- [x] Run the full suite and confirm GREEN (Durable Run 117/117, Interop 136/136, others unchanged).

### Task 5: High-risk approval interacting with recovery

- [x] Write tests: an unapproved high-risk tool never reaches the executor; an approved one runs exactly once; approval arriving later is re-dispatched on recovery; a denied approval is traceable and sanitized.
- [x] Fix 1 — recovery predicate: key off the derived `denied` flag instead of the observation reason code. The old predicate only matched when an observer had already reported `verified`, so a refusal followed by an observer `unknown` was silently treated as "read-back eligible".
- [x] Fix 2 — pause idempotency: a repeated resume wrote `loop.started` but its `loop.paused` was deduplicated by `{attempt_id}:paused`, leaving the run stuck in `running` with no closing event. The pause key now carries the resume round.
- [x] Run the full suite and confirm GREEN (Durable Run 112/112, Interop 136/136, others unchanged).

## Known boundaries

- The dispatcher authorizes per attempt from a host-owned token provider; it does not rotate credentials, cache grants, or implement rate limiting.
- `now_provider` is host-supplied, so clock trust is the host's responsibility.
- High-risk approval is only plumbed (`approval_provider`); no approval workflow is exercised by these tests.
- Refusal is detected from the derived `action_not_executed` reason code; renaming that code requires updating the recovery predicate.
