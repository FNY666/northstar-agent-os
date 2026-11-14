# Real Action-Failure Recovery Evaluation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task with verification checkpoints.

**Goal:** Measure whether the real DeepSeek agent can recover from one injected execution-time tool failure, rather than measuring only planning mistakes and postcondition correction.

**Architecture:** The benchmark fixture may request one bounded, host-controlled transient failure for a specific registered action. `live_benchmark.py` injects that failure through `AgentHarness`'s existing host-only fault hook, shared across rounds so it fires once globally; the model never receives a privileged failure control or credential. The existing `AgentLoop` records `step.action_failed`, the `AgentDriver` re-plans because the failure is not a refusal, and the benchmark independently counts evidence events plus final host verification.

**Tech Stack:** Python 3 standard library, existing `AgentHarness` fault hook, `AgentDriver`, `AgentLoop` evidence JSONL, `TypedPlannerAdapter`, OpenAI-compatible DeepSeek Flash, unittest.

## Global Constraints

- Work only in `/var/minis/workspace/northstar-agent-os-local-only`.
- Do not touch the public clone, `research-route-journal`, remotes, fetch, push, or remote branches.
- Do not read or print credential values; only use the configured environment-variable name.
- Every new production behavior follows RED → GREEN TDD; run the failing test before implementation.
- Fault injection is host-owned test/evaluation control only; it is never accepted from model output or exposed as authorization.
- Inject at most three failures per task and only for the declared registered action IDs.
- A task is successful only when a governed round finishes and the host independently verifies the deliverable.
- Preserve existing fail-closed semantics: `ToolRefused` stops/rejects; `ToolExecutionFailed` may be observed and re-planned.
- Use the already verified low-cost model configuration: DeepSeek V4 Flash via OpenRouter, reasoning off, `max_output_tokens=2048`.
- After each commit, refresh `/var/minis/shared/northstar-local-only-20260910.bundle` and verify a clone.

---

### Task 1: Fixture-Safe Fault Injection and Offline Telemetry

**Files:**
- Modify: `components/northstar-durable-run/live_benchmark.py`
- Modify: `components/northstar-durable-run/tests/test_live_benchmark.py`
- Modify: `components/northstar-durable-run/agent_driver.py` only if a stable round/evidence accessor is needed

**Interfaces:**
- Fixture optional field: `fault: {"action_id": str, "count": int}`. Only `repo.read`, `workspace.list`, and `workspace.write` are accepted; `count` is an integer from 1 through 3. Unknown fields, unknown actions, zero/negative/over-limit counts are rejected.
- `live_benchmark._run_one()` creates a shared mutable fault state for the task and a host-owned `harness_builder(run, evidence_path)`. The injected hook raises a generic execution exception only while remaining count is positive, then becomes inert for later rounds.
- Each task result adds `fault`, `faults_injected`, `action_failures`, and `recovered_after_action_failure`. `action_failures` is counted from task-scoped evidence JSONL event type `step.action_failed`, not from model claims. `recovered_after_action_failure` is true only when `faults_injected > 0`, `action_failures > 0`, and the final host-verified result is `ok`.
- Benchmark summary adds `fault_tasks`, `faults_injected`, `action_failures`, and `recovered_after_action_failure`.

- [x] **Step 1: Write failing fixture and telemetry tests**

Add tests for valid fault parsing, malformed fault rejection, one-shot shared injection across two rounds, evidence-derived action-failure counting, and a fake benchmark task that finishes only after the injected write failure is removed.

- [x] **Step 2: Run focused tests to verify RED**

```sh
cd components/northstar-durable-run
PYTHONPATH=.:../northstar-run-contract:../northstar-host \
  python3 -m unittest tests.test_live_benchmark
```

Expected: the new tests fail because fault fixtures and telemetry fields are not implemented.

- [x] **Step 3: Implement bounded fixture validation and shared injection**

Validate the fault object in `_validate_task`. In `_run_one`, create a shared `fault_state` and `harness_builder`; pass `faults={action_id: hook}` into every round's `AgentHarness`. The hook must decrement once and raise `RuntimeError("injected transient execution failure")`; it must not copy exception text into evidence.

- [x] **Step 4: Implement evidence-derived recovery telemetry**

After `driver.run`, scan only the task's own `round-*.evidence.jsonl` files and count `step.action_failed`. Add the task and summary fields without storing prompt content, request headers, or credentials. A missing/malformed evidence line must produce a bounded diagnostic failure, not a fabricated recovery count.

- [x] **Step 5: Run focused tests to verify GREEN**

Run the same focused command and require every test to pass.

- [x] **Step 6: Run the affected offline regression**

```sh
PYTHONPATH=.:../northstar-run-contract:../northstar-host \
  python3 -m unittest tests.test_agent_driver tests.test_live_benchmark
```

Expected: all tests pass, including existing re-planning and refusal boundaries.

---

### Task 2: Real Transient-Failure Task

**Files:**
- Create: `components/northstar-durable-run/live/tasks/04-transient-write-recovery.json`
- Modify: `components/northstar-durable-run/README.md`
- Modify: `.github/workflows/test.yml` if the new module/test coverage needs a compile entry

**Interfaces:**
- The fixture declares one `workspace.write` fault with `count: 1` and a host-owned `contains` expectation for the final report.
- The task goal explicitly requires reading the seed and writing one deliverable, so the model must cross the real read/write boundary. The benchmark, not the model, injects the transient failure.

- [x] **Step 1: Add the real recovery fixture**

Create a small task with `README.md`, a data file, a goal requiring `out/recovery.md`, and `fault: {"action_id":"workspace.write","count":1}`. The expectation must contain stable facts from the seed and must not assert the model's exact prose.

- [x] **Step 2: Run fixture validation and offline benchmark tests**

```sh
PYTHONPATH=.:../northstar-run-contract:../northstar-host \
  python3 -m unittest tests.test_live_benchmark
```

Expected: all tests pass and the new fixture loads.

- [x] **Step 3: Run the real recovery task**

```sh
rm -rf /tmp/northstar-live-recovery
PYTHONPATH=.:../northstar-run-contract:../northstar-host \
  python3 live_benchmark.py \
  --tasks live/tasks/04-transient-write-recovery.json \
  --endpoint https://openrouter.ai/api/v1/chat/completions \
  --key-env OPENROUTER_API_KEY \
  --model deepseek/deepseek-v4-flash \
  --provider openrouter \
  --reasoning off \
  --max-output-tokens 2048 \
  --sandbox /tmp/northstar-live-recovery \
  --report /tmp/northstar-live-recovery/report.json
```

Inspect the report and evidence. Required evidence: at least one `step.action_failed`, a later governed round or retry with the fault inactive, `action_failures >= 1`, `recovered_after_action_failure=true`, and an independently verified deliverable. If the model fails, report the actual result and do not silently retry until success.

- [x] **Step 4: Archive the recovery run**

Copy the report, fixture, deliverable, and task-scoped evidence into `/var/minis/shared/northstar-live-runs/2026-09-11-action-failure-recovery/` and validate stable invariants: non-empty evidence, failure event present, final report `ok=true`, and no credential/prompt fields.

---

### Task 3: Full Verification and Commit

**Files:**
- Modify: `components/northstar-durable-run/README.md`
- Modify: `docs/superpowers/plans/2026-09-11-real-action-failure-recovery.md`
- Modify: `.learnings/` only for verified new failures or corrections

- [x] **Step 1: Document the new metric and its ceiling**

Document the difference between planner re-planning, action-failure recovery, and postcondition verification. State that one injected transient write failure is not proof of arbitrary crash recovery or exactly-once external side effects.

- [x] **Step 2: Run complete verification**

Durable Run/Contract/Host/Sidecar/Docs/compile/diff/credential checks passed. Interop had a pre-existing intermittent process/concurrency failure in the first full run and three bounded full reruns; the focused failing test and later full reruns were retained, so this plan does not claim Interop stability for this slice.

Run Durable Run, Contract, Host, Interop, Sidecar, Docs, `py_compile`, `git diff --check`, and a credential-pattern scan. Require clean output and zero failures before claiming completion.

- [x] **Step 3: Commit and refresh the shared bundle**

Committed as `7ee6ec8`; bundle refreshed to HEAD `7ee6ec8` with 36 commits; `git bundle verify` and a fresh clone passed; local-only workspace is clean. Interop stability caveat remains explicitly recorded above.

---

## Self-Review

- The injection is host-owned and bounded; model output cannot request it.
- The same fault state spans rounds, preventing the benchmark from accidentally injecting the same failure forever.
- Evidence, not model claims, determines action-failure and recovery metrics.
- Refusal remains fail-closed and is not counted as recoverable execution failure.
- The real task uses a fresh sandbox and does not touch repository files outside the benchmark workspace.
- The result demonstrates one controlled execution-failure recovery, not production crash consistency or exactly-once semantics.
