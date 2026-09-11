# Agent Exploration and Evaluation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task with verification checkpoints.

**Goal:** Give the local agent a governed read-only `workspace.list` exploration tool and measure the real DeepSeek planner across several independently sandboxed tasks.

**Architecture:** `workspace.list` is a host-registered, bounded, symlink-safe read action. It returns names, kinds, and bounded file sizes but never file content; the existing independent observer verifies that the requested directory was safely inspected. The real benchmark reuses `AgentDriver` and `OpenAICompatiblePlannerCaller`, gives every task a fresh sandbox and evidence directory, captures provider usage through an injected transport, and reports task success, rounds, model calls, recovery, and observed cost.

**Tech Stack:** Python 3 standard library, existing `ActionGateway`, `GovernedActionDispatcher`, `AgentHarness`, `AgentDriver`, `OpenAICompatiblePlannerCaller`, OpenRouter OpenAI-compatible API, unittest.

## Global Constraints

- Work only in `/var/minis/workspace/northstar-agent-os-local-only`.
- Do not touch the public clone, `research-route-journal`, remotes, fetch, push, or remote branches.
- Do not read or print credential values; only use the configured environment-variable name.
- Every new production behavior follows RED → GREEN TDD; run the failing test before implementation.
- Every real task gets a fresh sandbox and fresh evidence files; stale evidence is a hard error.
- A task is successful only when the governed round finishes and the host independently verifies the deliverable.
- Use a bounded model output budget and bounded rounds; report actual cost/usage when the provider supplies it.
- After committing, refresh `/var/minis/shared/northstar-local-only-20260910.bundle` and verify a clone.

---

### Task 1: Governed Workspace Listing

**Files:**
- Create: `components/northstar-durable-run/workspace_list.py`
- Create: `components/northstar-durable-run/tests/test_workspace_list.py`
- Modify: `components/northstar-durable-run/action_gateway.py` only if a shared tool result contract is required
- Modify: `components/northstar-durable-run/agent_entry.py` to register `workspace.list`, expose its host executor, publish its schema, verify `listing_ok`, and expose a bounded host-side listing for the driver
- Modify: `components/northstar-durable-run/agent_driver.py` to collect list observations without treating directory listings as file reads
- Modify: `components/northstar-durable-run/tests/test_agent_entry.py` and `tests/test_agent_driver.py` for governed list and observation coverage
- Modify: `components/northstar-durable-run/README.md` and `.github/workflows/test.yml`

**Interfaces:**
- `WorkspaceListResult(path: str, entries: tuple[dict[str, Any], ...])` with `as_output() -> dict[str, Any]`.
- `WorkspaceListTool(root, *, max_entries=128, max_depth=8, allowed_prefixes=None).__call__(payload)` accepts exactly `{"prefix", "max_depth", "max_entries"}`. `prefix` may be `""` for the root; all non-empty prefixes are relative and reject absolute paths, `..`, empty components, backslashes, NULs, symlinked components, and non-directories.
- Each entry contains only `path`, `kind` (`file` or `directory`), and `size_bytes` for files. Symlinks are never followed or returned. Results are sorted and bounded.
- `AgentHarness` registers action id `workspace.list` with capability/scope `workspace:read`, low risk, and a host executor returning `WorkspaceListResult.as_output()`.
- `AgentHarness.observe()` recognizes `listing_ok`; `AgentHarness.inspect_listing()` returns a bounded independent filesystem listing for the driver.
- `AgentDriver._observe()` records a list observation for `workspace.list` and records file observations only for read/write actions.

- [ ] **Step 1: Write failing unit tests for the list contract**

Add tests for: root listing; nested prefix; sorted/bounded output; exact payload validation; traversal/absolute/backslash/NUL rejection; symlinked intermediate and symlink entry rejection; directory-only prefix; and no file content in output.

- [ ] **Step 2: Run the focused tests to verify RED**

Run:

```sh
cd components/northstar-durable-run
PYTHONPATH=.:../northstar-run-contract:../northstar-host python3 -m unittest tests.test_workspace_list
```

Expected: import failure because `workspace_list.py` does not exist.

- [ ] **Step 3: Implement the minimal bounded list tool**

Use a host-resolved root and `O_NOFOLLOW` directory walking. Create no files, follow no symlink, and return only bounded metadata. Use `ToolRefused` for inadmissible payloads and `ToolExecutionFailed` only for filesystem failures after the action has started.

- [ ] **Step 4: Run the focused list tests to verify GREEN**

Run the same command and require all list tests to pass with zero errors.

- [ ] **Step 5: Wire the tool through the harness and driver**

Add the action schema, gateway registration, observer postcondition, independent list inspection, and list-specific driver observation. Add regression tests proving an admitted `workspace.list` step is authorized, finishes, and exposes metadata but not content.

- [ ] **Step 6: Run the affected test set**

```sh
PYTHONPATH=.:../northstar-run-contract:../northstar-host python3 -m unittest \
  tests.test_workspace_list tests.test_agent_entry tests.test_agent_driver
```

Expected: all tests pass.

- [ ] **Step 7: Update docs and compile coverage**

Document the action's non-content boundary in `README.md` and include `workspace_list.py` in the durable-run `py_compile` command.

---

### Task 2: Real Multi-Task Evaluation

**Files:**
- Create: `components/northstar-durable-run/live_benchmark.py`
- Create: `components/northstar-durable-run/live/tasks/01-column-report.json`
- Create: `components/northstar-durable-run/live/tasks/02-release-note.json`
- Create: `components/northstar-durable-run/live/tasks/03-score-audit.json`
- Create: `components/northstar-durable-run/tests/test_live_benchmark.py`
- Modify: `components/northstar-durable-run/live_run.py` only if a shared fixture/parser helper is extracted
- Modify: `components/northstar-durable-run/README.md` and `.github/workflows/test.yml`

**Interfaces:**
- `load_live_tasks(path) -> tuple[dict[str, Any], ...]` validates unique `task_id`, non-empty `goal`, string `seed`, and valid `expect` entries (`content`, `digest`, `contains`, or `absent`).
- `UsageRecorderTransport(endpoint transport) -> callable(request, timeout) -> bytes` delegates to `urlopen`, records response `usage.cost`, `prompt_tokens`, `completion_tokens`, and `total_tokens`, and never records credentials or message content.
- `run_live_benchmark(tasks, *, endpoint, key_env, model, provider, model_revision, reasoning_effort, max_output_tokens, sandbox, max_rounds) -> dict` runs each task under `sandbox/<task_id>/`, with distinct evidence, and returns `{schema_version, model, planner, tasks, summary}`. Summary fields: `total`, `ok`, `success_rate`, `total_rounds`, `total_model_calls`, `recovered_tasks`, `total_cost`, `prompt_tokens`, `completion_tokens`.
- `main()` accepts `--tasks`, `--endpoint`, `--key-env`, `--model`, `--provider`, `--reasoning`, `--max-output-tokens`, `--sandbox`, `--report`, and `--max-tasks`; exit 0 only if every selected task is independently verified.

- [ ] **Step 1: Write failing benchmark tests**

Test fixture loading rejects duplicate IDs and malformed expectations; a fake transport reports usage without leaking request authorization or content; a scripted planner run produces correct summary counts; and a failed task makes exit status/report `ok=false`.

- [ ] **Step 2: Run benchmark tests to verify RED**

```sh
cd components/northstar-durable-run
PYTHONPATH=.:../northstar-run-contract:../northstar-host python3 -m unittest tests.test_live_benchmark
```

Expected: import failure because `live_benchmark.py` does not exist.

- [ ] **Step 3: Implement fixture validation, usage recording, and benchmark orchestration**

Reuse `ExpectedArtifact`, `AgentDriver`, and `TypedPlannerAdapter`; do not duplicate execution or verification logic. Give every task a fresh directory and reject pre-existing task sandboxes/evidence. Use the injected transport to capture only provider usage metadata.

- [ ] **Step 4: Run benchmark tests to verify GREEN**

Run the focused test command again and require all tests to pass.

- [ ] **Step 5: Add three deterministic live task fixtures**

Use small local seed files and host-owned `contains` expectations. At least one task must require read-then-replan; at least one must require a recovery round; no task may require network access or command execution.

- [ ] **Step 6: Run the real DeepSeek benchmark**

```sh
PYTHONPATH=.:../northstar-run-contract:../northstar-host \
python3 live_benchmark.py \
  --tasks live/tasks \
  --endpoint https://openrouter.ai/api/v1/chat/completions \
  --key-env OPENROUTER_API_KEY \
  --model deepseek/deepseek-v4-flash \
  --provider openrouter \
  --reasoning off \
  --max-output-tokens 8192 \
  --sandbox /tmp/northstar-live-benchmark \
  --report /tmp/northstar-live-benchmark/report.json
```

Inspect every task result, every failure, total calls, rounds, recovery count, and provider-reported cost. Archive the report, fixtures, deliverables, and evidence under `/var/minis/shared/northstar-live-runs/<date>-multi-task/`.

- [ ] **Step 7: Run the complete regression suite and commit**

Run durable-run plus Contract, Host, Interop, Sidecar, Docs, `py_compile`, `git diff --check`, and credential scan. Commit the two slices separately if both are independently green; refresh and clone-verify the shared bundle after each commit.

---

## Self-Review

- The list tool is independently testable before harness wiring.
- The benchmark is testable without network through injected transport and scripted planners.
- Real-model costs are bounded by `max_output_tokens`, rounds, and task count.
- Refusals, uncertain observations, and stale evidence remain fail-closed.
- No task depends on shell execution, network tools, or credentials in model context.
- The only live provider used is the already verified OpenRouter DeepSeek Flash path.
