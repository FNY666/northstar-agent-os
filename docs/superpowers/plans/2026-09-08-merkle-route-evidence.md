# Merkle Route Evidence Bundle Research Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or **superpowers:executing-plans** to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an independent tamper-evident Merkle commitment and inclusion-proof layer over sanitized Route Evidence audit lines.

**Architecture:** Build ordered, domain-separated Merkle leaves from canonical sanitized audit records. A bundle stores the root digest, leaf count, schema version, and canonical line digests; proofs bind a leaf index to the root and reject reordered, replaced, or out-of-range evidence. This is an evidence-integrity layer, not authorization, replay, or backend execution proof.

**Tech Stack:** Python 3.10+, standard library, hashlib, json, dataclasses, unittest.

## Global Constraints

- Work only in `/var/minis/workspace/northstar-agent-os-research-journal`.
- Do not modify public checkout or `/var/minis/workspace/northstar-agent-os-local-only`.
- Do not push, merge, cherry-pick, or create a PR.
- Do not store prompts, secrets, opaque context, raw outputs, or credentials.
- Preserve event ordering; duplicate-last-node padding must be deterministic and domain-separated.
- Merkle proof verification must fail closed on root, index, count, direction, digest, or schema mismatch.

---

### Task 1: Merkle primitives RED tests

**Files:**
- Create: `components/northstar-agent-interop/evidence_bundle.py`
- Create: `components/northstar-agent-interop/tests/test_evidence_bundle.py`

**Interfaces:**
- `EvidenceLeaf(index, digest, payload_digest)`
- `MerkleProof(index, leaf_count, siblings)`
- `EvidenceBundle(root_digest, leaf_count, schema_version, leaf_digests)`
- `build_bundle(events) -> EvidenceBundle`
- `make_proof(bundle, index) -> MerkleProof`
- `verify_proof(bundle, event, proof) -> None`

- [ ] Write RED tests for deterministic root, empty-bundle rejection, order sensitivity, tampered leaf rejection, wrong index/count rejection, proof round trip, and duplicate-last padding.
- [ ] Run focused tests and observe RED because the module does not exist.
- [ ] Implement canonical sanitized payload hashing with `leaf\0` and `node\0` domain separators.

### Task 2: Bundle serialization and independent verification

**Files:**
- Modify: `components/northstar-agent-interop/evidence_bundle.py`
- Modify: `components/northstar-agent-interop/tests/test_evidence_bundle.py`

- [ ] Add strict `to_dict/from_dict` schemas with `northstar.evidence-bundle.v1`.
- [ ] Add bundle file export with `fsync`, mode `0600`, and a manifest digest.
- [ ] Verify that raw prompt/output/secret fields are rejected before leaf construction.

### Task 3: Route/Lineage integration

**Files:**
- Create: `components/northstar-agent-interop/tests/test_evidence_bundle_integration.py`
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`

- [ ] Build a bundle from selected RouteJournal/Lineage audit projections.
- [ ] Prove an individual route receipt without exposing other events.
- [ ] Reject stale bundle schema, changed leaf ordering, changed sequence, and mismatched decision fingerprint.
- [ ] Document that Merkle inclusion proves evidence integrity only; it does not authorize actions or prove backend correctness.

### Acceptance

- Existing Interop baseline plus evidence-bundle tests pass.
- Compile, diff check, and sensitive scan pass.
- A deliberate proof-verification guard rollback turns a proof test RED.
- Commit stays on the research branch only.
