# Plan Evidence Decision Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Bind a minimal agent plan evidence manifest to an exact replayed readiness gate, so a consumer can audit why the plan's evidence preconditions were ready, blocked, or unknown without receiving action authorization.

**Architecture:** `EvidencePlanManifest` contains canonical, bounded step identifiers and unique claim requirements. `make_plan_evidence_decision` maps its requirements to the existing readiness evaluator and binds the manifest, manifest digest, full gate wire form, gate digest, and readiness state in a domain-separated decision digest. Verification reparses and replays the readiness gate; external decision, manifest, and gate pins determine fully pinned vs unpinned verification.

**Tech Stack:** Python 3.10+, standard library, existing evidence readiness gate/state projection modules, `unittest`. No network and no new dependency.

## Global Constraints

- Research worktree only; no local-only, main, integration-next, arena, runtime, merge, cherry-pick, or remote push changes.
- The manifest binds evidence prerequisites only; it does not carry executable actions, raw prompt text, secrets, or provider output.
- A decision state is `ready`, `blocked`, or `unknown`; `execution_authorized` is always false.
- `ready` means only the manifest's declared evidence claims were projected supported. It is not safety, completeness, factual truth, or permission to execute.
- Missing external decision/manifest/gate pins return `decision-verified-unpinned`.

---

### Task 1: Canonical evidence plan manifests (RED first)

**Files:**
- Create: `components/northstar-agent-interop/plan_evidence_decision.py`
- Create: `components/northstar-agent-interop/tests/test_plan_evidence_decision.py`

**Interfaces:**
- `EvidencePlanStep(step_id, claim_digest, rationale)`
- `EvidencePlanManifest.to_dict()/from_dict()`
- `make_plan_evidence_decision(manifest, projections) -> PlanEvidenceDecision`

- [x] Test canonical unique plan steps/claims, deterministic manifest digest, and strict wire form.
- [x] Reject duplicate step ids, duplicate claim requirements, malformed identifiers, and raw action/prompt fields.
- [x] Run focused tests RED before implementation.

### Task 2: Decision replay and external pin semantics

**Files:**
- Modify: `components/northstar-agent-interop/plan_evidence_decision.py`
- Modify: `components/northstar-agent-interop/tests/test_plan_evidence_decision.py`

**Interfaces:**
- `PlanEvidenceDecision.to_dict()/from_dict()`
- `verify_plan_evidence_decision(decision, *, manifest, projections, expected_decision_digest=None, expected_manifest_digest=None, expected_gate_digest=None) -> PlanDecisionVerdict`

- [x] Test supported/blocked/unknown plan states and permanent `execution_authorized=False`.
- [x] Recompute the gate and reject altered manifest, requirement, projection, state, gate, or digest.
- [x] Distinguish fully pinned `decision-verified` from unpinned verification.
- [x] Preserve projection unresolved boundaries in the decision verdict.

### Task 3: Documentation and local regression

**Files:**
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`
- Create: `docs/superpowers/plans/2026-09-15-plan-evidence-decision.md`

- [x] Document evidence readiness vs action authorization and requirement-scope limits.
- [x] Run focused tests, full Interop regression, `py_compile`, `git diff --check`, and sensitive scan.
- [x] Commit locally only; do not notify other sessions or push.
