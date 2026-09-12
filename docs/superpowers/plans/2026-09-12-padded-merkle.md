# Padded Merkle Commitment and Non-Inclusion Proof Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or **superpowers:executing-plans** to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a versioned evidence commitment that pads to a power of two with domain-separated pad leaves and can prove both inclusion and non-inclusion without changing v1 roots or consumers.

**Architecture:** `evidence_bundle_v2.py` sorts unique event leaf digests, pads the leaf layer to the next power of two with a domain-separated constant that is not any real leaf, and commits the full fixed tree. Inclusion disclosures carry one path. Absence proofs carry either the boundary proof or two adjacent real-leaf proofs; the verifier checks both paths, the sorted-neighbor relation, and a pinned root. v1 remains untouched and rejects v2 through its strict schema.

**Tech Stack:** Python 3.10+, standard library, existing `EvidenceError`/disclosure verdict vocabulary, `unittest`. No network and no new dependency.

## Global Constraints

- Research worktree only: no local-only writes, no main/integration-next/arena writes, no merge, no cherry-pick.
- `evidence_bundle.py` v1 root calculation and schema are immutable.
- Pad leaves must be domain-separated and must never equal a real event leaf.
- Duplicate real leaf digests are rejected; non-inclusion over a multiset is not sound without a duplicate policy.
- A `verified` non-inclusion result requires a pinned expected root; self-carried roots are `verified-unpinned`.
- An absence proof proves absence from the committed sorted set only; it does not prove an event never existed in the world.
- No raw secrets, prompts, credentials, or output fields may enter event leaves; reuse the v1 sensitive-key rejection rule.

---

### Task 1: Padded v2 bundle and inclusion disclosure (RED first)

**Files:**
- Create: `components/northstar-agent-interop/evidence_bundle_v2.py`
- Create: `components/northstar-agent-interop/tests/test_evidence_bundle_v2.py`

**Interfaces:**
- `SCHEMA_V2 = "northstar.evidence-bundle.v2"`
- `PaddedEvidenceBundle(root_digest, leaf_count, padded_count, leaf_digests, schema_version)`
- `build_bundle_v2(events) -> PaddedEvidenceBundle`
- `make_inclusion_v2(bundle, index) -> InclusionProofV2`
- `verify_inclusion_v2(proof, subject, *, expected_root=None) -> DisclosureVerdict`

- [x] Test deterministic roots for 1..17 events and power-of-two boundaries.
- [x] Test duplicate rejection, sensitive-key rejection, and v1/v2 schema isolation.
- [x] Test inclusion paths for real leaves and rejection of pad positions.
- [x] Run focused tests RED before implementation.

### Task 2: Non-inclusion proof

**Files:**
- Modify: `components/northstar-agent-interop/evidence_bundle_v2.py`
- Modify: `components/northstar-agent-interop/tests/test_evidence_bundle_v2.py`

**Interfaces:**
- `AbsenceProofV2(root_digest, target_digest, padded_count, predecessor, successor)`
- `make_absence_v2(bundle, target) -> AbsenceProofV2`
- `verify_absence_v2(proof, *, expected_root=None) -> DisclosureVerdict`

- [x] For a target before the first leaf or after the last leaf, prove the boundary with one neighbor path.
- [x] For a target between two leaves, prove both adjacent sorted neighbors and their strict ordering.
- [x] Reject a target that is actually present.
- [x] Reject tampered paths, wrong roots, wrong padded counts, unsorted neighbors, and pad leaves presented as real neighbors.
- [x] Mark unpinned roots as `verified-unpinned`, never `verified`.

### Task 3: Documentation and regression

**Files:**
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`
- Create: `docs/superpowers/plans/2026-09-12-padded-merkle.md`

- [x] Document v1/v2 compatibility, padding semantics, duplicate policy, and the exact meaning of absence.
- [x] Run focused tests; full Interop regression is blocked by an unrelated intermittent existing ProcessAdapter failure, while the isolated ProcessAdapter pair passes 5/5 runs; `py_compile`, `git diff --check`, and sensitive scan pass.
- [ ] Commit locally; notify before pushing and wait for explicit acknowledgement.
