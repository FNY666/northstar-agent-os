# Persistent Causal Evidence Store Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `test-driven-development` task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Persist verified causal edges in a versioned append-only store with restart recovery and externally pinned cursor protection.

**Architecture:** `causal_store.py` stores only canonical `CausalEdge` records in a v2 envelope. Each envelope has a contiguous sequence, predecessor digest, and own digest. The store validates each edge against `CausalEdge.from_dict()` before writing and verifies the complete chain during recovery. A caller-held cursor detects suffix rollback; the store is evidence plumbing, not authorization.

**Tech Stack:** Python 3.12 stdlib, JSONL, SHA-256, `fcntl`, `fsync`, `unittest`; no network or remote writes.

## Global Constraints

- Modify only `/var/minis/workspace/northstar-agent-os-local-only`.
- Public checkout, integration, arena branches, research-route-journal, and remote servers remain frozen.
- No research source is copied or cherry-picked.
- Persist only typed causal edges and bounded digests; never credentials, prompts, raw output, or signed tokens.
- Existing 108 Interop tests must remain passing; the new store adds 10 tests and the current worktree contains 119 tests in total.
- Invalid schema, sequence, predecessor, edge digest, duplicate edge, or cursor mismatch fails closed.

## Public Interfaces

```python
@dataclass(frozen=True)
class EvidenceCursor:
    sequence: int
    record_digest: str

@dataclass(frozen=True)
class CausalEvidenceRecord:
    schema_version: str
    sequence: int
    prev_record_digest: str | None
    record_digest: str
    edge: CausalEdge

@dataclass(frozen=True)
class EvidenceRecovery:
    verdict: str  # verified
    records: tuple[CausalEvidenceRecord, ...]
    cursor: EvidenceCursor | None

class CausalEvidenceStore:
    def __init__(self, path: str | Path): ...
    def append(self, edge: CausalEdge) -> CausalEvidenceRecord: ...
    def recover(self, *, expected_cursor: EvidenceCursor | None = None) -> EvidenceRecovery: ...
```

### Task 1: Envelope, append, and restart recovery

- [x] Write RED tests for canonical record digest, predecessor link, append idempotency, and recovery after a new store instance.
- [x] Confirm RED with the focused unittest command.
- [x] Implement strict envelope parsing, flock-protected append, fsync, and full recovery verification.
- [x] Confirm GREEN.

### Task 2: Cursor rollback and corruption rejection

- [x] Write RED tests for modified record, sequence gap, duplicate edge and suffix rollback against `EvidenceCursor`.
- [x] Confirm RED, implement cursor and strict chain checks, confirm GREEN.

### Task 3: Lineage integration and verification

- [x] Deliberately do not add `CausalGraph.persist(store)` or `CausalEvidenceStore.graph()`; the standalone typed edge store is the smaller non-duplicative boundary demonstrated by the tests.
- [x] Run focused store tests, py_compile, documentation tests, diff check, sensitive scan, and public checkout status check.
- [x] Obtain a clean standard-order full Interop regression with no failures or unexplained environment timeouts.
- [ ] Create a local-only commit after fresh verification.

## Execution notes

- The missing `causal_store` import produced the initial RED; the first two envelope/restart tests then passed after the minimal implementation.
- Additional RED tests found and fixed forged edge-digest acceptance and duplicate-edge replay acceptance.
- External-lock and four-process same-edge idempotency tests were separately rerun with `ResourceWarning` treated as an error and passed.
- The first standard-order full run reported one existing process-adapter integration timeout; focused reruns, a 105-test prelude followed by the target, five independent target runs, and an alternate-order 118-test run passed. A later standard-order run again reproduced the same timeout, so this is not yet accepted as a clean full-suite gate.
- No production fix has been guessed for the unrelated flaky process-adapter test; the causal-store slice remains uncommitted until the standard-order gate is explained or independently stabilized.


A hash chain alone cannot detect deletion of its final record; an external `EvidenceCursor` is required. Persisted causal evidence does not authenticate a handoff and does not authorize backend actions.
