# Evidence Readiness Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or **superpowers:executing-plans** to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Evaluate whether an agent plan's declared evidence prerequisites are supported, blocked, or unknown without granting permission to execute the plan.

**Architecture:** `EvidenceRequirement` names a claim digest and optional rationale. `evaluate_readiness` takes a plan identifier, requirements, and `ClaimProjection` values from the evidence state layer. It produces a canonical `EvidenceReadinessGate` with a digest binding the exact requirement set and observed projections. Only `supported` claims meet a requirement; missing/unknown claims yield `unknown`, while conflicted/insufficient/unverifiable claims yield `blocked`. The gate has no authorization API and exposes `execution_authorized=False` in all cases.

**Tech Stack:** Python 3.10+, standard library, existing `evidence_state_projection`, `unittest`. No network and no new dependency.

## Global Constraints

- Research worktree only; no local-only, main, integration-next, arena, runtime, merge, cherry-pick, or remote push changes.
- Readiness is evidence precondition evaluation, never a permission decision or tool execution trigger.
- `ready` only says all declared evidence requirements are currently projected `supported`; it does not prove the plan is safe or authorized.
- A claim absent from the projection set is `unknown`, not assumed false or supported.
- Conflicted evidence is always blocked; no winner is selected.
- Canonical gate digest binds plan id, requirements, observed projection wire forms, decision, blockers, and unknown claims; it carries no prompt, event body, secret, or provider output.

---

### Task 1: Requirement schema and readiness decision (RED first)

**Files:**
- Create: `components/northstar-agent-interop/evidence_readiness_gate.py`
- Create: `components/northstar-agent-interop/tests/test_evidence_readiness_gate.py`

**Interfaces:**
- `EvidenceRequirement(claim_digest, rationale)`
- `EvidenceReadinessGate.to_dict()/from_dict()`
- `evaluate_readiness(plan_id, requirements, projections) -> EvidenceReadinessGate`

- [x] Test all-supported → `ready`, missing/unknown → `unknown`, and conflicted/insufficient/unverifiable → `blocked`.
- [x] Test duplicate requirements, claim/projection mismatch, malformed projections, and invalid plan identifiers fail closed.
- [x] Test canonical deterministic wire form and gate digest binding.
- [x] Run focused tests RED before implementation.

### Task 2: Provenance and non-authorization boundary

**Files:**
- Modify: `components/northstar-agent-interop/evidence_readiness_gate.py`
- Modify: `components/northstar-agent-interop/tests/test_evidence_readiness_gate.py`

- [x] Preserve every observed projection digest/reason/unverified field needed to explain blockers.
- [x] Mark `execution_authorized=False` for every gate state, including `ready`.
- [x] Reject tampered gate fields, mismatched requirement/projection digests, and altered digest.
- [x] Ensure no raw subject/prompt/event/secret text is serialized.

### Task 3: Documentation and local regression

**Files:**
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`
- Create: `docs/superpowers/plans/2026-09-15-evidence-readiness-gate.md`

- [x] Document readiness vs authorization and conservative treatment of missing/conflicting evidence.
- [x] Run focused tests, full Interop regression, `py_compile`, `git diff --check`, and sensitive scan.
- [x] Commit locally only; do not notify other sessions or push.
