# Governed Repo Read Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `test-driven-development` task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Connect an admitted AgentPlan to one real, bounded, read-only repository tool without allowing path traversal, symlink escape, writes, or unbounded output.

**Architecture:** `RepoReadTool` is a host-owned callable bound to one private workspace root. It accepts only a relative path and byte limit from the admitted `PlanStep.input_payload`, resolves the path without following symlinks, rejects directories and escapes, and returns bounded content plus a digest. It performs no writes and remains independent of any model caller.

**Tech Stack:** Python 3.12 standard library (`pathlib`, `hashlib`, `dataclasses`, `typing`, `unittest`); no network, shell, credentials, or external dependencies.

## Global Constraints

- Modify only `/var/minis/workspace/northstar-agent-os-local-only`.
- Public checkout, integration, arena refs, remotes, and servers remain frozen.
- Read tool is strictly read-only and cannot invoke shell or arbitrary callable fields.
- Workspace root is host-owned; model input cannot replace it.
- Reject absolute paths, traversal, symlink components, directories, oversized reads, malformed payloads, and missing files.
- Return bounded metadata/content only; do not return secrets or unrestricted filesystem paths.

## Files

- Create: `components/northstar-durable-run/repo_read.py` — host-owned safe read callable.
- Create: `components/northstar-durable-run/tests/test_repo_read.py` — TDD path, bound, and integration tests.
- Modify: `components/northstar-durable-run/README.md` — describe the first real read-only tool.

### Task 1: Safe read contract

- [ ] Write RED tests for valid reads, traversal, absolute paths, symlinks, directories, missing files, invalid payloads, and output bounds.
- [ ] Run focused tests and confirm missing module failure.
- [ ] Implement `RepoReadTool` with host-owned root and bounded `RepoReadResult`.
- [ ] Run focused tests and confirm GREEN.

### Task 2: AgentLoop integration

- [x] Write RED test proving an admitted planner plan can execute `repo.read` and finish only after an independent observer verifies the returned digest.
- [x] Implement only the minimal adapter needed to register the tool; do not give the model direct filesystem authority.
- [x] Run focused tests and confirm GREEN.

### Task 2b: Action-failure traceability (found while integrating)

- [x] Forensic probe showed an action that raises is recorded as nothing: trace only had `step.attempted` then `step.observed`.
- [x] Write RED tests: action error produces exactly one traceable event, exception message never reaches evidence, successful action produces no such event.
- [x] Record `step.action_failed` with the failure kind only; keep observer-based recovery legal for committed-unknown cases.
- [x] Run focused tests and confirm GREEN.

### Task 3: Documentation and verification

- [x] Document read-only status and known local-only ceiling.
- [x] Run Repo Read, Planner + Durable Run, Interop, Host, Contract, docs, compile, diff, and sensitive checks.
- [x] Confirm public checkout unchanged.
- [ ] Create one local-only commit; never push.
