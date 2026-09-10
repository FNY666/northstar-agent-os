# Crash-Consistent Evidence Log Rotation and Compaction Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or **superpowers:executing-plans** to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the append-only route/evidence log grow without bound in *records* while keeping every already-acknowledged record provably accounted for — including after rotation, compaction, and a crash at any step.

**Architecture:** Records stay chained per record (`previous_digest` → `record_digest`) inside a segment. Rotation seals the active segment and publishes its digest in a manifest that is replaced atomically; compaction deletes a sealed segment's records and keeps only that digest. The verdict distinguishes three states — `replayable` (every record readable and chained), `digest-only` (some segment survives as a digest and still anchors the chain), `unverifiable` (a segment is missing, orphaned, or does not match its digest).

**Tech Stack:** Python 3.10+, standard library, `unittest`.

## Global Constraints

- Research worktree only.
- No public/local-only writes, push, PR, merge, or cherry-pick.
- No credentials or real backend calls.
- Never adopt an unregistered segment file: an orphan is reported, not read.
- The manifest is authoritative for *what exists*; segment content is authoritative for *what it says*. They must agree, or the verdict is `unverifiable`.
- Compaction must never silently change chain continuity: a compacted segment keeps its `last_digest` so the next segment still chains to it.

---

### Task 1: Records, segments, and the sealed manifest (RED first)

**Files:**
- Create: `components/northstar-agent-interop/evidence_rotation.py`
- Create: `components/northstar-agent-interop/tests/test_evidence_rotation.py`

**Interfaces:**
- `SegmentRef(segment_id, first_sequence, last_sequence, record_count, first_digest, last_digest, segment_digest, compacted)`
- `RotationVerdict(state, reasons, segments)`
- `SegmentedEvidenceLog(root, *, max_records_per_segment)` with `append/rotate/compact/read_segment/read_all/segments/verify`
- `verify_log(root) -> RotationVerdict`

- [ ] Test append/read roundtrip and manual rotation sealing a segment.
- [ ] Test roll-on-next-append when the active segment is full.
- [ ] Test that the segment digest is content-bound (a one-byte edit is detected).
- [ ] Run RED before implementation.

### Task 2: Crash recovery

**Files:**
- Modify: `components/northstar-agent-interop/evidence_rotation.py`
- Modify: `components/northstar-agent-interop/tests/test_evidence_rotation.py`

- [ ] A truncated tail line is ignored, not repaired.
- [ ] A rotation interrupted between manifest publish and segment rename is completed on load (digest-verified, never name-trusted).
- [ ] An unregistered `segment-*.log` is reported as `orphan_segment` and not adopted.
- [ ] A missing segment, a missing manifest with sealed segments, and a corrupt manifest fail closed.

### Task 3: Compaction

**Files:**
- Modify: `components/northstar-agent-interop/evidence_rotation.py`
- Modify: `components/northstar-agent-interop/tests/test_evidence_rotation.py`

- [ ] Compaction removes records, keeps the digest, and degrades the verdict to `digest-only` — never to `replayable`.
- [ ] `read_segment` on a compacted segment fails closed; `read_all` skips it.
- [ ] Compacting twice, or compacting the active segment, is rejected.
- [ ] The checkpoint chain survives restart with a compacted segment in front of it.

### Task 4: Research documentation and full regression

**Files:**
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`

- [ ] Document what rotation and compaction prove, and the readability/provability split.
- [ ] Run the complete Interop suite, compile, diff, sensitive scan.
- [ ] Commit research-only; do not push or contact other sessions during routine work.
