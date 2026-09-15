# Evidence State Projection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or **superpowers:executing-plans** to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Derive a deterministic, conflict-preserving claim state from admission witnesses and conflict observations so an agent can inspect evidence conditions without silently choosing facts or authorizing action.

**Architecture:** `EvidenceStateProjection` consumes strict `AdmissionWitness` values and strict `ConflictObservation` values. It groups them by claim digest and projects one state per claim: `supported`, `conflicted`, `insufficient`, `unverifiable`, or `unknown`. Conflict observations dominate support; admission witnesses are replayed only structurally here, not re-authorized. The projection includes every package digest/reason as provenance and exposes `actionable=False` for every state except fully supported, but callers still own authorization.

**Tech Stack:** Python 3.10+, standard library, existing admission witness/conflict ledger modules, `unittest`. No network and no new dependency.

## Global Constraints

- Research worktree only; no local-only, main, integration-next, arena, runtime, merge, cherry-pick, or remote push changes.
- Projection is descriptive state reduction, not truth resolution, authorization, or policy evaluation.
- A `conflicted` state never selects a winner; it preserves conflict ids, package digests, and reasons.
- A witness with `insufficient` admission remains insufficient even if its package is internally valid.
- A missing external witness/policy pin makes the witness result `unverifiable` in this projection unless caller explicitly supplies a verified witness object.
- Raw prompt, event bodies, secrets, and provider output never enter the projection; only claim/package/witness/conflict digests, states, and reasons are retained.

---

### Task 1: Claim projections (RED first)

**Files:**
- Create: `components/northstar-agent-interop/evidence_state_projection.py`
- Create: `components/northstar-agent-interop/tests/test_evidence_state_projection.py`

**Interfaces:**
- `ClaimProjection.to_dict()/from_dict()`
- `project_claim(claim_digest, witnesses, conflicts=()) -> ClaimProjection`
- States: `supported`, `conflicted`, `insufficient`, `unverifiable`, `unknown`

- [x] Test a fully pinned admissible witness projects to supported.
- [x] Test insufficient and malformed/unverifiable inputs project correctly.
- [x] Test empty inputs produce unknown.
- [x] Run focused tests RED before implementation.

### Task 2: Conflict dominance and provenance

**Files:**
- Modify: `components/northstar-agent-interop/evidence_state_projection.py`
- Modify: `components/northstar-agent-interop/tests/test_evidence_state_projection.py`

- [x] A same-claim conflict observation dominates otherwise admissible witnesses.
- [x] Different-claim conflict observations are ignored for the target claim.
- [x] Canonical provenance ordering preserves all package/witness/conflict digests and reasons without choosing a winner.
- [x] Wire form is strict and deterministic; malformed inputs fail closed.

### Task 3: Multi-claim snapshot and local regression

**Files:**
- Modify: `components/northstar-agent-interop/evidence_state_projection.py`
- Modify: `components/northstar-agent-interop/tests/test_evidence_state_projection.py`
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`
- Create: `docs/superpowers/plans/2026-09-15-evidence-state-projection.md`

**Interfaces:**
- `project_state(witnesses, conflicts=()) -> dict[str, ClaimProjection]`

- [x] Project multiple claims deterministically and omit no observed claim.
- [x] Mark `actionable` only for supported, non-conflicted, fully pinned witness evidence; document that callers still authorize actions.
- [x] Run focused tests, full Interop regression, `py_compile`, `git diff --check`, and sensitive scan.
- [x] Commit locally only; do not notify other sessions or push.
