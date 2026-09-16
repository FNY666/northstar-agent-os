# Autonomous Continuation Checkpoint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a host-owned, deterministic continuation checkpoint that proves whether a paused AgentRuntime may resume under the same goal, governance surface, transcript evidence, and budget snapshot.

**Architecture:** Add a pure runtime module that canonicalizes only host-owned continuation inputs into a sealed checkpoint. Verification re-computes every binding against current observed inputs and returns `current`, `stale`, or `unknown`; it never authorizes execution. AgentRuntime integration remains additive: the first MVP exposes explicit capture/verify APIs before any automatic `continue_session` gate is changed.

**Tech Stack:** Python 3.12 stdlib (`dataclasses`, `hashlib`, `json`), existing RuntimeConfig / Budget / SessionStore record shapes, unittest.

## Global Constraints

- Local-only research worktree; remote remains frozen at `c371a15`; no push.
- Every checkpoint verdict has `execution_authorized=False`.
- Canonical JSON and SHA-256 digests; reject unknown/missing wire fields.
- Do not trust a model-declared completion or continuation claim.
- TDD: RED → minimal implementation → targeted suite → mutation → runtime + interop suites.

---

### Task 1: Checkpoint data contract

**Files:**
- Create: `components/northstar-agent-runtime/autonomy_checkpoint.py`
- Create: `components/northstar-agent-runtime/tests/test_autonomy_checkpoint.py`

**Interfaces:**
- Produces: `AutonomyCheckpoint`, `AutonomyCheckpointError`, `capture_checkpoint()`.
- Checkpoint binds `goal_digest`, `session_id`, `runtime_digest`, `transcript_digest`, `budget_digest`, phase, injected `observed_at`, and `checkpoint_digest`.

- [x] Write RED tests for deterministic capture, exact wire round-trip, tampered digest rejection, and forbidden execution authorization.
- [x] Implement canonical hashing and strict wire parsing.
- [x] Verify targeted tests pass; runtime suite 408/408 and interop suite 620/620 pass.
- [x] Mutation-check digest validation and commit.

### Task 2: Freshness and drift verification

**Files:**
- Modify: `components/northstar-agent-runtime/autonomy_checkpoint.py`
- Modify: `components/northstar-agent-runtime/tests/test_autonomy_checkpoint.py`

**Interfaces:**
- Produces: `ContinuationVerdict` and `verify_checkpoint()`.
- Verification compares a checkpoint with current host-observed goal/runtime/transcript/budget inputs and emits `current`, `stale`, or `unknown`; never an execution grant.

- [x] Write RED tests for goal/policy/transcript/budget drift, no external pin (`current-unpinned`), matching external checkpoint pin (`current`), and invalid current inputs.
- [x] Implement comparison and reason precedence.
- [x] Run mutation checks proving each binding matters; runtime suite 413/413 and interop suite 620/620 pass.
- [x] Commit.

### Task 3: Explicit runtime adapter

**Files:**
- Modify: `components/northstar-agent-runtime/loop.py`
- Modify: `components/northstar-agent-runtime/tests/test_loop.py`
- Modify: `components/northstar-agent-runtime/tests/test_autonomy_checkpoint.py`

**Interfaces:**
- Produces: additive `AgentRuntime.capture_continuation_checkpoint()` and `verify_continuation_checkpoint()` methods.
- Adapter derives inputs from `RuntimeConfig.as_dict()`, registered tool manifest, `SessionStore.read()`, and `Budget.status()`; it must not change `continue_session()` yet.

- [x] Write RED tests using ScriptedProvider and a SessionStore.
- [x] Implement the adapter with no hidden I/O or auto-resume.
- [x] Verify checkpoint drift after a transcript/config/tool-governance change.
- [x] Run mutation checks and both suites; commit.

## Self-Review

- Spec coverage: Task 1 covers durable identity; Task 2 covers stale/replay detection; Task 3 binds the capability to real AgentRuntime inputs without prematurely changing execution semantics.
- Placeholder scan: no TODO/TBD entries; every task declares files and interfaces.
- Type consistency: all later tasks consume the concrete types introduced by Task 1.
