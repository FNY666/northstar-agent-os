# Evidence State Witness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or **superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Bind a projected claim state to its exact admission witnesses and conflict observations, so an agent can replay the reduction and detect substituted state provenance.

**Architecture:** `EvidenceStateWitness` embeds canonical AdmissionWitness and ConflictObservation wire forms plus the derived ClaimProjection. Creation calls the existing `project_claim`; verification strictly reparses every source, reprojects the claim, compares all projection fields, and validates a domain-separated witness digest. An external state-witness digest determines `state-witness-verified` vs `state-witness-verified-unpinned`.

**Tech Stack:** Python 3.10+, standard library, existing admission witness/conflict ledger/state projection modules, `unittest`. No network and no new dependency.

## Global Constraints

- Research worktree only; no local-only, main, integration-next, arena, runtime, merge, cherry-pick, or remote push changes.
- State witness is a deterministic reduction receipt, not truth, authorization, or a replacement for replaying package admission.
- `unknown` with no source is not witnessable: absence of supplied evidence cannot become an attested fact.
- Sources must be canonical and same-claim; conflict observations never select a winner.
- External witness digest missing returns unpinned state; source-level unresolved boundaries remain explicit.
- No raw prompt, event, secret, or provider output is included beyond the existing source wire forms.

---

### Task 1: State witness schema and deterministic reduction (RED first)

**Files:**
- Create: `components/northstar-agent-interop/evidence_state_witness.py`
- Create: `components/northstar-agent-interop/tests/test_evidence_state_witness.py`

**Interfaces:**
- `EvidenceStateWitness.to_dict()/from_dict()`
- `make_state_witness(claim_digest, admission_witnesses, conflicts=()) -> EvidenceStateWitness`
- `StateWitnessVerdict(state, claimed_state, reasons, unverified, state_digest)`

- [x] Test deterministic supported and conflict witnesses.
- [x] Test strict schema, same-claim source validation, canonical source ordering, and unknown-without-source refusal.
- [x] Test no raw prompt/event/secret is added by the state witness.
- [x] Run focused tests RED before implementation.

### Task 2: Replay verification and external pin semantics

**Files:**
- Modify: `components/northstar-agent-interop/evidence_state_witness.py`
- Modify: `components/northstar-agent-interop/tests/test_evidence_state_witness.py`

**Interfaces:**
- `verify_state_witness(witness, *, expected_state_digest=None) -> StateWitnessVerdict`

- [x] Reparse/reproject and compare every projected field exactly.
- [x] Reject tampered projection, witness, conflict, claim, ordering, or state digest.
- [x] Distinguish externally pinned `state-witness-verified` from unpinned witness verification.
- [x] Preserve projection unverified fields, never turn them into authorization.

### Task 3: Documentation and local regression

**Files:**
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`
- Create: `docs/superpowers/plans/2026-09-15-evidence-state-witness.md`

- [x] Document reduction replay, no-source unknown boundary, and state-vs-authorization separation.
- [x] Run focused tests, full Interop regression, `py_compile`, `git diff --check`, and sensitive scan.
- [x] Commit locally only; do not notify other sessions or push.
