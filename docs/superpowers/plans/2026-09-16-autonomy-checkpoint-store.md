# Autonomous Checkpoint Store Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans or subagent-driven-development task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Persist host-owned continuation checkpoints across process restarts with single-writer locking, append-only records, and detectable local tamper/truncation.

**Architecture:** The runtime component receives a standalone `AutonomyCheckpointStore`, rather than importing durable-run `EventStore`: durable-run records require RunContract/EventContract identities and lifecycle semantics that an AgentRuntime continuation does not have, while EventStore exposes no lock boundary for independent writers. The new store persists only already non-authorizing checkpoints, uses canonical hash-chained JSONL plus an atomically written head witness, and returns non-authorizing resolution states.

**Tech Stack:** Python stdlib (`fcntl`, `hashlib`, `json`, `os`, `tempfile`), existing `AutonomyCheckpoint`, unittest.

## Global Constraints

- Local-only, remote frozen at `c371a15`, no push.
- Store cannot authorize execution; every resolution has `execution_authorized=False`.
- Closed wire fields, fsync append, same-host flock, atomic head witness write.
- Missing/tampered/truncated history is never reported as current.

---

### Task 1: Append-only checkpoint store

**Files:**
- Create: `components/northstar-agent-runtime/autonomy_checkpoint_store.py`
- Create: `components/northstar-agent-runtime/tests/test_autonomy_checkpoint_store.py`

**Interfaces:**
- Produces: `AutonomyCheckpointStore`, `CheckpointRecord`, `CheckpointResolution`, `AutonomyCheckpointStoreError`.
- `append(checkpoint) -> CheckpointRecord`; `resolve(session_id, expected_record_digest=None) -> CheckpointResolution`.

- [x] Write RED tests for reopen/restore, pin semantics, independent writers, tamper, and tail truncation.
- [x] Implement hash-chained JSONL, flock, fsync, and atomic head witness.
- [x] Mutation-check digest/chain validation; runtime suite 423/423 and interop suite 620/620 pass.
- [x] Commit.

### Task 2: Runtime persistence adapter

**Files:**
- Modify: `components/northstar-agent-runtime/loop.py`
- Modify: `components/northstar-agent-runtime/tests/test_autonomy_checkpoint.py`

**Interfaces:**
- Add optional explicit `persist_continuation_checkpoint(store, goal, observed_at)` and `resolve_persisted_continuation_checkpoint(store, goal, now, expected_record_digest=None)` APIs.
- APIs compose checkpoint capture/verify with store resolution; they do not auto-resume or authorize execution.

- [ ] Write RED tests for restart persistence and tampered store → unknown.
- [ ] Implement additive adapter only.
- [ ] Mutation-check and run both suites.
- [ ] Commit.
