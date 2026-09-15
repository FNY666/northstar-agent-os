# Evidence Admission and Conflict Preservation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or **superpowers:executing-plans** to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Evaluate a portable evidence package against an explicit evidence policy and preserve contradictory packages as conflicts without turning admission into authorization.

**Architecture:** `EvidenceAdmissionPolicy` names required external pins, disallowed unresolved boundaries, and whether a verifier receipt is mandatory. `admit_package` calls the existing package verifier, derives a stable claim digest from the subject's route/agent/payload/decision identity, and returns `admissible`, `insufficient`, or `unverifiable`. `compare_admissions` groups results only by that claim digest and returns `conflicting` when their evidence root or claimed evidence state diverges; it never selects a winner.

**Tech Stack:** Python 3.10+, standard library, existing `EvidencePackage` verifier, `unittest`. No network and no new dependency.

## Global Constraints

- Research worktree only; no local-only, main, integration-next, arena, runtime, merge, cherry-pick, or remote push changes.
- An admission result is evidence policy evaluation, never action authorization.
- A self-carried digest/pin is not external trust; missing required pins are `insufficient`.
- Same-key HMAC, receipt-only, and root/key/chain/package unpinned conditions stay explicit policy inputs.
- Conflict detection preserves both package digests and both reasons; it never resolves a conflict.
- Claim identity is a canonical digest of route id, target agent, provider, payload digest, decision fingerprint, and event digest. It does not contain raw prompt or output.

---

### Task 1: Policy and package admission (RED first)

**Files:**
- Create: `components/northstar-agent-interop/evidence_admission.py`
- Create: `components/northstar-agent-interop/tests/test_evidence_admission.py`

**Interfaces:**
- `EvidenceAdmissionPolicy.to_dict()/from_dict()`
- `AdmissionResult(state, policy_id, claim_digest, evidence_root, claimed_evidence_state, package_digest, reasons, unverified)`
- `admit_package(package, policy, *, key_anchor, evidence_scheme, expected_root=None, expected_package_digest=None, expected_checkpoint_chain_digest=None, receipt_scheme=None, expected_challenge_id=None, expected_verifier_id=None) -> AdmissionResult`

- [x] Test explicit external pin requirements, receipt requirements, and forbidden observations.
- [x] Test valid package → admissible only under a policy that permits its remaining boundaries.
- [x] Test invalid package → unverifiable and missing policy requirements → insufficient.
- [x] Run focused tests RED before implementation.

### Task 2: Conflict preservation

**Files:**
- Modify: `components/northstar-agent-interop/evidence_admission.py`
- Modify: `components/northstar-agent-interop/tests/test_evidence_admission.py`

**Interfaces:**
- `ConflictComparison(state, claim_digest, left_package_digest, right_package_digest, reasons)`
- `compare_admissions(left, right) -> ConflictComparison`

- [x] Same claim + same evidence root/state → consistent.
- [x] Same claim + different evidence root or claimed state → conflicting.
- [x] Different claim digests → incomparable.
- [x] Reject malformed admission objects and never select a winning package.

### Task 3: Documentation and local regression

**Files:**
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`
- Create: `docs/superpowers/plans/2026-09-15-evidence-admission.md`

- [x] Document evidence admission, policy boundaries, and conflict preservation.
- [x] Run focused tests, full Interop regression, `py_compile`, `git diff --check`, and sensitive scan.
- [x] Commit locally only; do not notify other sessions or push.
