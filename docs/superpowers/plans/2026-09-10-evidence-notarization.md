# Evidence Notarization Envelope Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or **superpowers:executing-plans** to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Package a verified evidence claim into a deterministic, portable envelope that can be checked offline with a pluggable signature verifier and pinned evidence roots.

**Architecture:** The producer first verifies the existing full evidence layers, then emits only the subject event, a minimal Merkle disclosure, the proof attestation, the key-history records, and the checkpoint head. The envelope signs a canonical payload excluding the signature. Verification checks structure, signature, key-history chain, checkpoint binding, attestation roots, and disclosure; it never treats the signer declaration as authorization.

**Tech Stack:** Python 3.10+, standard library, existing interop evidence modules, `unittest`. No new dependency and no built-in asymmetric cryptography claim.

## Global Constraints

- Research worktree only: no local-only writes, no main/integration-next/arena writes, no merge, no cherry-pick.
- Existing v1 evidence schemas and root algorithms remain unchanged.
- Secret material never enters the envelope, key-history records, or test artifacts.
- `SignatureScheme` is injectable. `HMACSignatureScheme` is explicitly same-key compatibility; public-key schemes are host-provided and not implemented here.
- `signer` is an identity declaration, not an authorization decision.
- Missing or unpinned roots remain `verified-unpinned`; never upgrade them to `verified`.

---

### Task 1: Envelope schema and producer (RED first)

**Files:**
- Create: `components/northstar-agent-interop/evidence_notarization.py`
- Create: `components/northstar-agent-interop/tests/test_evidence_notarization.py`

**Interfaces:**
- `SignatureScheme.sign(payload: bytes, *, key_id: str) -> str`
- `SignatureScheme.verify(payload: bytes, signature: str, *, key_id: str) -> bool`
- `EvidenceEnvelope.to_dict()/from_dict()`
- `build_envelope(..., index, key_id, history, signer, scheme) -> EvidenceEnvelope`

- [ ] Test a complete producer path with a deterministic injected scheme.
- [ ] Test canonical payload determinism and absence of secret material.
- [ ] Test producer refusal for unverified evidence, revoked key, malformed signer, and missing checkpoint head.
- [ ] Run the focused tests RED before implementation.

### Task 2: Offline verifier and fail-closed semantics

**Files:**
- Modify: `components/northstar-agent-interop/evidence_notarization.py`
- Modify: `components/northstar-agent-interop/tests/test_evidence_notarization.py`

**Interfaces:**
- `EnvelopeVerdict(state, reasons, unverified)`
- `verify_envelope(envelope, *, anchor, scheme, expected_root=None) -> EnvelopeVerdict`
- `HMACSignatureScheme` for same-key compatibility tests only.

- [ ] Verify the signature over the exact canonical payload.
- [ ] Verify embedded key-history records against the pinned anchor and key state.
- [ ] Verify checkpoint head, attestation roots, and minimal disclosure against the expected root.
- [ ] Propagate root-unpinned and key-anchor-unpinned as explicit unverified reasons.
- [ ] Reject any tampering of subject, disclosure, attestation, key history, checkpoint, signer, or signature.

### Task 3: Documentation and regression

**Files:**
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`
- Create: `docs/superpowers/plans/2026-09-10-evidence-notarization.md`

- [ ] Document the portable envelope and its evidence-vs-authorization boundary.
- [ ] State clearly that injected public-key schemes are supported by interface only; no asymmetric implementation is shipped.
- [ ] Run focused tests, full Interop regression, `py_compile`, `git diff --check`, and sensitive scan.
- [ ] Commit locally; push only after the notification → explicit acknowledgement protocol.
