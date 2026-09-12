# Cross-Layer Evidence Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or **superpowers:executing-plans** to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the composed evidence verifier actually enforce cross-layer identity, deadline, payload, and decision consistency before returning `verified`.

**Architecture:** Keep the existing `cross_layer_verifier.verify_cross_layer` pure and unchanged. The composition verifier adapts the route record, terminal lineage event, bundle binding, and handoff into its explicit cross-layer input shape after all lower-layer checks pass. Any mismatch becomes `unknown`; a failed layer remains `failed`. Existing v1 proof APIs stay unchanged.

**Tech Stack:** Python 3.10+, standard library, existing interoperability modules, `unittest`.

## Global Constraints

- Research worktree only; no local-only, main, integration-next, arena, runtime, merge, or cherry-pick changes.
- Do not weaken any lower-layer verifier or convert `unknown` to `verified`.
- Cross-layer checks are evidence consistency, not authorization.
- No raw prompt, secret, token, or provider output enters the cross-layer adapter.

---

### Task 1: Regression tests for the missing gate (RED first)

**Files:**
- Modify: `components/northstar-agent-interop/tests/test_evidence_proof.py`

- [x] Add a terminal payload mismatch test that fails before the gate is wired.
- [x] Add a lineage route identity mismatch test that fails before the gate is wired.
- [x] Run focused tests RED and confirm the existing verifier incorrectly returned `verified`.

### Task 2: Wire the gate

**Files:**
- Modify: `components/northstar-agent-interop/evidence_proof.py`

- [x] Preserve the existing chain, lineage-bundle, Merkle, and checkpoint-root checks.
- [x] Adapt route, terminal lineage, bundle binding, and handoff into `verify_cross_layer`.
- [x] Preserve `failed` for a failed lower layer and return `unknown` for cross-layer mismatch.
- [x] Run focused tests GREEN.

### Task 3: Documentation and regression

**Files:**
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`

- [x] Document the previously missing gate and its evidence-only boundary.
- [x] Run the full Interop suite, `py_compile`, `git diff --check`, and sensitive scan.
- [x] Commit locally; push only after notification and explicit acknowledgement.
