# End-to-End Route Evidence Proof Verifier Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or **superpowers:executing-plans** to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Compose Route Ledger, Lineage, Merkle inclusion proof, Evidence Chain checkpoint, and Handoff into one independent proof verifier.

**Architecture:** The verifier is pure and read-only. It first validates chain continuity and lineage semantics, then validates bundle identity and Merkle inclusion, then cross-checks route/Handoff/terminal identity and deadline. It returns `verified`, `failed`, or `unknown`; it never authorizes or executes.

**Tech Stack:** Python 3.10+, standard library, existing research modules, unittest.

## Global Constraints

- Research worktree only.
- No public/local-only writes, push, PR, merge, or cherry-pick.
- No credentials or real backend calls.
- `verified` requires every independent evidence layer to pass; missing/ambiguous evidence is `unknown`.

---

### Task 1: Proof input schema and RED tests

**Files:**
- Create: `components/northstar-agent-interop/evidence_proof.py`
- Create: `components/northstar-agent-interop/tests/test_evidence_proof.py`

**Interfaces:**
- `ProofResult(verdict, reasons)`
- `verify_route_evidence_proof(route_record, lineage, bundle, checkpoint_chain, event, proof, handoff) -> ProofResult`

- [ ] Test all matching layers → verified.
- [ ] Test Merkle tamper, lineage hash mismatch, checkpoint chain mismatch, Handoff mismatch, failed terminal, and missing layer → fail closed.
- [ ] Run RED before implementation.

### Task 2: Compose independent verifiers

**Files:**
- Modify: `components/northstar-agent-interop/evidence_proof.py`
- Modify: `components/northstar-agent-interop/tests/test_evidence_proof.py`

- [ ] Call `verify_chain`, `verify_lineage`, `verify_lineage_bundle`, `verify_proof`, and cross-layer checks without bypassing any failure.
- [ ] Require event sequence and terminal digest to match bundle binding.
- [ ] Ensure a failed/unknown lower-layer verdict cannot become verified at the top.

### Task 3: Research documentation and full regression

**Files:**
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`

- [ ] Document proof composition, evidence-vs-authorization boundary, and remaining production gaps.
- [ ] Run complete Interop suite, compile, diff, sensitive scan.
- [ ] Commit research-only; do not push or contact other sessions during routine work.
