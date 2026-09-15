# Evidence Conflict Ledger Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or **superpowers:executing-plans** to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Persist contradictory admission witnesses as append-only observations without resolving them or silently selecting a winner.

**Architecture:** `EvidenceConflictLedger` accepts two strict `AdmissionWitness` objects, validates that they concern the same claim but differ in evidence root or claimed evidence state, canonically orders only their witness digests for idempotency, and appends a hash-chained JSONL observation. The canonical ordering is not a ranking. Recovery verifies sequence, predecessor digest, record digest, and strict schema; a truncated tail is ignored and a complete invalid record fails closed.

**Tech Stack:** Python 3.10+, standard library (`json`, `hashlib`, `fcntl`, `os`, `multiprocessing`), existing `admission_witness`, `unittest`. No network and no new dependency.

## Global Constraints

- Research worktree only; no local-only, main, integration-next, arena, runtime, merge, cherry-pick, or remote push changes.
- A ledger observes conflicts; it does not resolve them, authorize actions, or state which witness is true.
- Observations reference only witness/package/claim/root/policy digests, states, and conflict reasons; no raw prompt, event body, secret, or provider output enters the ledger.
- The pair order is canonical only for deduplication and must never be presented as winner/loser.
- `flock` provides same-host idempotency only; no cross-host exactly-once claim.
- A truncated final line is ignored; complete malformed/tampered/reordered/gapped history is `unverifiable` and blocks mutation.

---

### Task 1: Conflict observation and durable idempotency (RED first)

**Files:**
- Create: `components/northstar-agent-interop/evidence_conflict_ledger.py`
- Create: `components/northstar-agent-interop/tests/test_evidence_conflict_ledger.py`

**Interfaces:**
- `ConflictObservation.to_dict()/from_dict()`
- `EvidenceConflictLedger(path)`
- `record_conflict(left_witness, right_witness) -> ConflictObservation`
- `verify() -> ConflictLedgerVerdict`

- [x] Test same-claim/different-root and same-claim/different-state conflicts.
- [x] Test reversed input order returns the same idempotent observation without creating a winner.
- [x] Test same evidence and different claims are refused rather than logged as conflicts.
- [x] Run focused tests RED before implementation.

### Task 2: Recovery and concurrency

**Files:**
- Modify: `components/northstar-agent-interop/evidence_conflict_ledger.py`
- Modify: `components/northstar-agent-interop/tests/test_evidence_conflict_ledger.py`

- [x] Restore conflict observations after restart.
- [x] Ignore a truncated final line; reject complete malformed, tampered, reordered, and missing history.
- [x] Same-host concurrent recording of an identical conflict yields exactly one durable record.
- [x] Assert no raw secret/prompt/event payload appears in persisted JSON.

### Task 3: Documentation and local regression

**Files:**
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`
- Create: `docs/superpowers/plans/2026-09-15-conflict-ledger.md`

- [x] Document conflict preservation and non-resolution semantics.
- [x] Run focused tests, full Interop regression, `py_compile`, `git diff --check`, and sensitive scan.
- [x] Commit locally only; do not notify other sessions or push.
