# Evidence Readiness Preflight Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax.

**Goal:** Revalidate plan evidence, readiness lease freshness, and lease-registry state together immediately before a caller considers an action, without granting permission or executing anything.

**Architecture:** `evaluate_preflight` composes existing plan-decision replay, readiness-lease verification, and registry-witness verification. It requires all three exact bindings and a current registry witness for `preflight-ready`; blocked/unknown/stale/revoked/unverifiable states remain distinct. The returned `EvidenceReadinessPreflight` contains only digests, states, reasons, and unresolved fields, with `execution_authorized=False` permanently enforced.

**Tech Stack:** Python 3.10+, standard library, existing evidence readiness modules, `unittest`. No network and no new dependency.

## Global Constraints

- Research worktree only; no local-only, main, integration-next, arena, runtime, merge, cherry-pick, or remote push changes.
- Preflight is a freshness and evidence-consistency check, not authorization and not execution.
- `preflight-ready` means only that the declared evidence decision is still ready, its lease is active, and its registry witness is current; it does not mean the action is safe or permitted.
- Any missing external pin is `preflight-unpinned`, never fully ready.
- Registry revocation/staleness/unverifiability dominates lease freshness; no stale lease may become ready.
- No raw action, command, prompt, event body, secret, or provider output enters the preflight artifact.

---

### Task 1: Preflight composition (RED first)

**Files:**
- Create: `components/northstar-agent-interop/evidence_readiness_preflight.py`
- Create: `components/northstar-agent-interop/tests/test_evidence_readiness_preflight.py`

**Interfaces:**
- `EvidenceReadinessPreflight.to_dict()/from_dict()`
- `evaluate_preflight(lease, registry_witness, registry, decision, manifest, projections, *, now, expected_lease_digest, expected_registry_witness_digest, expected_decision_digest, expected_manifest_digest, expected_gate_digest) -> EvidenceReadinessPreflight`

- [x] Test an active lease/current registry witness/ready decision → `preflight-ready` with authorization false.
- [x] Test blocked/unknown decision, expired lease, revoked lease, stale registry witness, and unverifiable registry → conservative non-ready states.
- [x] Run focused tests RED before implementation.

### Task 2: Strict replay and pin semantics

**Files:**
- Modify: `components/northstar-agent-interop/evidence_readiness_preflight.py`
- Modify: `components/northstar-agent-interop/tests/test_evidence_readiness_preflight.py`

- [x] Bind lease, registry witness, decision, manifest, gate, and claim digests exactly.
- [x] Reject changed source objects, mismatched lease/witness, altered state/reasons, and malformed wire data.
- [x] Missing external pins return `preflight-unpinned`; no state may return execution authorization.
- [x] Preserve all unresolved evidence fields from the underlying decision/lease/witness layers.

### Task 3: Documentation and local regression

**Files:**
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`
- Create: `docs/superpowers/plans/2026-09-15-evidence-readiness-preflight.md`

- [x] Document preflight freshness, registry revocation dominance, and non-authorization boundary.
- [x] Run focused tests, full Interop regression, `py_compile`, `git diff --check`, and sensitive scan.
- [x] Commit locally only; do not notify other sessions or push.
