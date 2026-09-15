# Portable Evidence Package Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or **superpowers:executing-plans** to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Bind an evidence envelope, complete checkpoint witness, key-history snapshot, and optional verifier receipt into one deterministic offline package without changing their existing schemas.

**Architecture:** `EvidencePackage` is a composition-only artifact. Build-time checks bind the envelope checkpoint head to the complete checkpoint witness, bind the snapshot to the envelope's embedded key history, and bind an optional verifier receipt to the exact envelope digest. Verification re-runs each component verifier and exposes missing external pins instead of promoting self-carried digests to trust.

**Tech Stack:** Python 3.10+, standard library, existing interop modules, `unittest`. No network and no new dependency.

## Global Constraints

- Research worktree only; no local-only, main, integration-next, arena, runtime, merge, cherry-pick, or remote push changes.
- Existing envelope, witness, snapshot, and receipt schemas remain unchanged.
- The package digest is an integrity binding, not a trust anchor; without an external package digest it is `verified-unpinned`.
- The package does not authorize actions, prove facts are true, or turn same-key HMAC into independent third-party verification.
- Optional verifier receipts describe an observation; they do not become evidence truth.

---

### Task 1: Composition package (RED first)

**Files:**
- Create: `components/northstar-agent-interop/evidence_package.py`
- Create: `components/northstar-agent-interop/tests/test_evidence_package.py`

**Interfaces:**
- `EvidencePackage.to_dict()/from_dict()`
- `build_package(envelope, checkpoint_witness, key_snapshot, verifier_receipt=None) -> EvidencePackage`
- `verify_package(package, *, key_anchor, evidence_scheme, expected_root=None, expected_package_digest=None, expected_checkpoint_chain_digest=None, receipt_scheme=None, expected_challenge_id=None, expected_verifier_id=None) -> PackageVerdict`

- [x] Test deterministic package creation and strict wire round-trip.
- [x] Test envelope/witness/snapshot binding and optional receipt binding.
- [x] Test package tampering and missing components fail closed.
- [x] Run focused tests RED before implementation.

### Task 2: External pin semantics and offline verification

**Files:**
- Modify: `components/northstar-agent-interop/evidence_package.py`
- Modify: `components/northstar-agent-interop/tests/test_evidence_package.py`

- [x] Require external package digest and checkpoint chain digest for `verified`.
- [x] Propagate envelope, witness, key-anchor, and receipt unverified boundaries.
- [x] Reject a receipt without its expected challenge/verifier or receipt scheme.
- [x] Preserve `receipt-only`, `same-key`, and `root-unpinned` distinctions.

### Task 3: Documentation and local regression

**Files:**
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`
- Create: `docs/superpowers/plans/2026-09-15-portable-evidence-package.md`

- [x] Document the package composition and the difference between integrity and trust anchors.
- [x] Run focused tests, full Interop regression, `py_compile`, `git diff --check`, and sensitive scan.
- [x] Commit locally only; do not notify other sessions or push.
