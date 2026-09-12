# Key-History Snapshot and As-Of Verdict Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or **superpowers:executing-plans** to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Verify a key's lifecycle state at an explicitly pinned history revision, so a later rotation or revocation does not erase the ability to reason about an earlier signed artifact.

**Architecture:** Add an independent `key_history_snapshot.py` layer over the immutable v1 `KeyRecord` format. A `KeyHistorySnapshot` binds a revision to the first-record anchor and the record digest at that revision. Verification parses and validates exactly that prefix; `verdict_at` derives the key state only from the verified prefix. Existing `KeyHistory.verdict` and `KeyRing` behavior remain unchanged.

**Tech Stack:** Python 3.10+, standard library, existing `key_lifecycle` records/digests, `unittest`. No network and no new dependency.

## Global Constraints

- Research worktree only; no local-only, main, integration-next, arena, runtime, merge, or cherry-pick changes.
- Existing key-history v1 record schema and current-state verdicts remain unchanged.
- A revision is ordering metadata, not wall-clock time; this layer makes no timestamp claim.
- A snapshot is trusted only when its head digest matches the recomputed prefix and its anchor matches the caller-pinned history anchor.
- Missing anchor returns an explicit unpinned result; it never silently becomes trusted evidence.
- Corruption inside the pinned prefix fails closed. Corruption strictly after a pinned prefix does not rewrite that already-pinned prefix.
- No key material enters snapshots or verdicts.

---

### Task 1: Strict history snapshots (RED first)

**Files:**
- Create: `components/northstar-agent-interop/key_history_snapshot.py`
- Create: `components/northstar-agent-interop/tests/test_key_history_snapshot.py`

**Interfaces:**
- `KeyHistorySnapshot(schema_version, revision, anchor_digest, head_digest)`
- `make_snapshot(history, revision=None) -> KeyHistorySnapshot`
- `verify_snapshot(history, snapshot) -> SnapshotVerdict`

- [x] Test latest and historical snapshots, strict wire round-trip, and invalid revision refusal.
- [x] Test anchor mismatch, head mismatch, missing history, and prefix corruption.
- [x] Test that corruption after a pinned prefix does not invalidate the prefix.
- [x] Run focused tests RED before implementation.

### Task 2: As-of key-state verdicts

**Files:**
- Modify: `components/northstar-agent-interop/key_history_snapshot.py`
- Modify: `components/northstar-agent-interop/tests/test_key_history_snapshot.py`

**Interfaces:**
- `HistoricalKeyVerdict(state, reasons, revision, head_digest)`
- `verdict_at(history, key_id, snapshot) -> HistoricalKeyVerdict`

- [x] At revision 1, an introduced key is trusted and a future key is unknown.
- [x] After rotation, the old key is trusted-retired and the new key is trusted.
- [x] After revocation, the revoked key is refused without rewriting earlier verdicts.
- [x] Propagate unpinned anchor, anchor mismatch, and unverifiable prefix explicitly.

### Task 3: Documentation and regression

**Files:**
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`
- Create: `docs/superpowers/plans/2026-09-12-key-history-snapshot.md`

- [x] Document revision-order semantics and the difference between historical state and trusted time.
- [x] Run focused tests, full Interop regression, `py_compile`, `git diff --check`, and sensitive scan.
- [x] Commit locally only; do not push or notify another session.
