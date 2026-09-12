# Verifier Receipt Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or **superpowers:executing-plans** to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a signed, challenge-bound receipt stating that a verifier checked one exact evidence envelope and observed a particular verification result, without confusing that statement with authorization or with the evidence itself.

**Architecture:** `issue_verification_receipt` consumes a persistent `ChallengeLedger` challenge, runs the existing offline envelope verifier, and signs a canonical receipt payload with a verifier-owned injected `SignatureScheme`. `verify_receipt` checks only the receipt's signature and bindings to the exact envelope, challenge, verifier, and expected evidence root; it deliberately returns `receipt-verified`, not `verified`, because it does not independently re-run the evidence verifier.

**Tech Stack:** Python 3.10+, standard library, existing `ChallengeLedger`, `EvidenceEnvelope`, `verify_envelope`, `SignatureScheme`, `unittest`. No network and no new dependency.

## Global Constraints

- Research worktree only; no local-only, main, integration-next, arena, runtime, merge, cherry-pick, or remote push changes.
- Existing envelope, challenge-ledger, and v1 evidence schemas remain unchanged.
- Receipt signatures bind the full envelope digest, verifier audience, challenge id, claimed evidence state, unverified fields, and evidence root.
- `signer`/`verifier_id` is an identity or audience declaration, never an authorization grant.
- A receipt is a signed statement about an observation; it is not proof that the evidence is truthful and not permission to act.
- Same-key HMAC receipt signatures are explicitly not third-party independent verification; injected public-key schemes remain host-provided.
- Challenge consumption is single-use and persistent; failure or replay must not silently issue a second receipt.
- Receipt issuance must preflight a challenge, finish signing, and consume only after a valid signature exists; a signing failure or key mismatch must not burn the challenge.

---

### Task 1: Receipt schema and issue path (RED first)

**Files:**
- Create: `components/northstar-agent-interop/verification_receipt.py`
- Create: `components/northstar-agent-interop/tests/test_verification_receipt.py`

**Interfaces:**
- `VerificationReceipt.to_dict()/from_dict()`
- `ReceiptVerification(state, claimed_evidence_state, reasons, unverified)`
- `issue_verification_receipt(envelope, ledger, *, challenge_id, verifier_id, evidence_anchor, evidence_scheme, receipt_key_id, receipt_scheme) -> VerificationReceipt`

- [x] Test a pinned successful envelope receipt and exact envelope/challenge/verifier bindings.
- [x] Test that challenge consumption survives restart and prevents a second receipt.
- [x] Test missing, expired, audience-mismatched, revoked, and invalid evidence paths fail closed.
- [x] Run focused tests RED before implementation.

### Task 2: Offline receipt verification

**Files:**
- Modify: `components/northstar-agent-interop/verification_receipt.py`
- Modify: `components/northstar-agent-interop/tests/test_verification_receipt.py`

**Interfaces:**
- `verify_receipt(receipt, *, envelope, expected_challenge_id, expected_verifier_id, expected_root=None, scheme) -> ReceiptVerification`

- [x] Verify the receipt signature over the exact canonical payload.
- [x] Reject altered envelope, challenge, verifier, evidence root, claimed state, unverified fields, key id, or signature.
- [x] Return `receipt-verified` rather than `verified`; preserve `claimed_evidence_state` and add `receipt-only` to the explicit boundary.
- [x] Return `receipt-verified` with `root-unpinned` warning when no expected root is supplied; never treat a self-carried root as a trusted anchor.
- [x] Mark same-key HMAC as unverified metadata.

### Task 3: Documentation and local regression

**Files:**
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`
- Create: `docs/superpowers/plans/2026-09-12-verifier-receipt.md`

- [x] Document verifier receipts, challenge consumption, signature boundary, and evidence-vs-authorization separation.
- [x] Run focused tests, full Interop regression, `py_compile`, `git diff --check`, and sensitive scan.
- [x] Commit locally only; do not notify other sessions or push.
