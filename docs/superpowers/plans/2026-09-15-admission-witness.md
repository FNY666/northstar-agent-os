# Policy-Bound Admission Witness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or **superpowers:executing-plans** to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Bind an admission result to the exact canonical evidence policy and exact package digest, so a later policy edit cannot rewrite what the admission meant.

**Architecture:** `AdmissionWitness` carries the canonical policy wire form and digest, the package/claim/evidence digests, the complete admission result fields, and a domain-separated witness digest. `make_admission_witness` reuses package admission. `verify_admission_witness` strictly parses the embedded policy, reruns admission under caller-supplied trust pins, and compares all replayed fields exactly. An external witness or policy digest is required for a fully pinned witness result.

**Tech Stack:** Python 3.10+, standard library, existing `evidence_admission` and `evidence_package` modules, `unittest`. No network and no new dependency.

## Global Constraints

- Research worktree only; no local-only, main, integration-next, arena, runtime, merge, cherry-pick, or remote push changes.
- Existing policy, package, receipt, witness, and envelope schemas remain unchanged.
- A policy id is not a policy commitment; only canonical `policy_digest` binds policy semantics.
- A witness is an auditable admission observation, not authorization and not an assertion that the evidence is true.
- The witness records admissible or insufficient policy results; malformed/unverifiable packages are not witnessable outcomes.
- Missing external witness/policy pins return `witness-verified-unpinned`, never a fully pinned result.

---

### Task 1: Admission witness schema and creation (RED first)

**Files:**
- Create: `components/northstar-agent-interop/admission_witness.py`
- Create: `components/northstar-agent-interop/tests/test_admission_witness.py`

**Interfaces:**
- `AdmissionWitness.to_dict()/from_dict()`
- `make_admission_witness(package, policy, *, key_anchor, evidence_scheme, ...) -> AdmissionWitness`
- `AdmissionWitnessVerdict(state, claimed_admission_state, reasons, unverified, witness_digest, policy_digest)`

- [x] Test deterministic wire form, strict schema, canonical policy digest, and secret/raw-prompt exclusion.
- [x] Test valid admissible and insufficient admission results can be witnessed.
- [x] Test malformed/unverifiable package admission is rejected rather than represented as a reliable witness.
- [x] Run focused tests RED before implementation.

### Task 2: Replay verification and external pins

**Files:**
- Modify: `components/northstar-agent-interop/admission_witness.py`
- Modify: `components/northstar-agent-interop/tests/test_admission_witness.py`

**Interfaces:**
- `verify_admission_witness(witness, package, *, expected_witness_digest=None, expected_policy_digest=None, key_anchor, evidence_scheme, ...) -> AdmissionWitnessVerdict`

- [x] Replay admission against the embedded canonical policy and compare every result field exactly.
- [x] Reject altered package, policy, policy digest, package digest, claim digest, result state, reasons, unverified fields, or witness digest.
- [x] Distinguish full `witness-verified` from `witness-verified-unpinned` when external pins are absent.
- [x] Preserve evidence-level unresolved boundaries and never convert witness verification into authorization.

### Task 3: Documentation and local regression

**Files:**
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`
- Create: `docs/superpowers/plans/2026-09-15-admission-witness.md`

- [x] Document policy commitments, replay semantics, and admission-vs-authorization boundary.
- [x] Run focused tests, full Interop regression, `py_compile`, `git diff --check`, and sensitive scan.
- [x] Commit locally only; do not notify other sessions or push.
