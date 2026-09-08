# Evidence Bundle Chain Research Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or **superpowers:executing-plans** to implement this plan task-by-step. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Chain multiple Merkle Route Evidence Bundles into tamper-evident ordered checkpoints.

**Architecture:** Each checkpoint commits a batch sequence, previous bundle root, current bundle root, evidence count, and canonical checkpoint digest. Verification requires exact predecessor continuity and rejects reorder, deletion, replacement, schema drift, or count changes. The chain is an evidence timeline, not authorization or backend proof.

**Tech Stack:** Python 3.10+, standard library, dataclasses, hashlib, json, unittest.

## Global Constraints

- Work only in `/var/minis/workspace/northstar-agent-os-research-journal`.
- No public checkout or local-only writes; no push/PR/merge/cherry-pick.
- No real backend execution or credentials.
- Checkpoint evidence contains only digests, counts, sequence, and bounded identity metadata.
- Fail closed on gaps, duplicate sequence, root mismatch, schema mismatch, or tampering.

---

### Task 1: Chain schema RED tests

**Files:**
- Create: `components/northstar-agent-interop/evidence_chain.py`
- Create: `components/northstar-agent-interop/tests/test_evidence_chain.py`

**Interfaces:**
- `EvidenceCheckpoint.from_dict(value) -> EvidenceCheckpoint`
- `EvidenceChain.append(bundle) -> EvidenceCheckpoint`
- `EvidenceChain.read() -> Iterator[EvidenceCheckpoint]`
- `verify_chain(chain) -> None`

- [ ] Test first checkpoint zero predecessor, monotonic batch sequence, previous root continuity, root/count binding, unknown field rejection, and digest stability.
- [ ] Implement canonical checkpoint schema with `northstar.evidence-chain.v1`.
- [ ] Implement append-only fsync persistence and strict read validation.

### Task 2: Tamper/reorder/deletion protection

**Files:**
- Modify: `components/northstar-agent-interop/evidence_chain.py`
- Modify: `components/northstar-agent-interop/tests/test_evidence_chain.py`

- [ ] Test reordered checkpoints, missing middle checkpoint, modified root/count, duplicate batch sequence, and schema mismatch.
- [ ] Make verification fail closed before returning any partial success.
- [ ] Add file round-trip with truncated tail semantics: truncated final line may be explicitly reported as incomplete, never silently treated as complete.

### Task 3: Bundle integration and boundary review

**Files:**
- Create: `components/northstar-agent-interop/tests/test_evidence_chain_integration.py`
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`

- [ ] Build two LineageEvidenceBundles, append them to a chain, verify continuity, and prove one bundle cannot be transplanted into another chain.
- [ ] Document evidence-chain limits: no distributed timestamp authority, no authorization, no backend execution guarantee.
- [ ] Run compile, diff check, sensitive scan, and complete Interop suite.
