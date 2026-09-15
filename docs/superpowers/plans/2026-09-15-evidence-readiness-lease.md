# Evidence Readiness Lease Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Bind a fully pinned `ready` plan evidence decision to an injected-time freshness lease, so stale or drifted readiness cannot be silently reused as a current evidence conclusion.

**Architecture:** `EvidenceReadinessLease` binds plan id, decision digest, manifest digest, gate digest, issued/expiry timestamps, and a domain-separated lease digest. Issuance replays the fully pinned plan decision and only permits a `ready` result. Verification reparses the lease, replays the exact decision against current projections, compares all source bindings, and reports valid, expired, or unpinned lease state. Every result has `execution_authorized=False`.

**Tech Stack:** Python 3.10+, standard library, existing `plan_evidence_decision`, `unittest`. No network and no new dependency.

## Global Constraints

- Research worktree only; no remote push, cross-session coordination, or shared-branch changes.
- Time is caller-injected ordering/freshness input, not trusted wall-clock proof.
- A lease is evidence freshness metadata, not permission to execute a plan.
- Issuance requires a fully pinned and replayed `ready` decision; blocked/unknown/unpinned decision evidence cannot issue a lease.
- Missing external lease digest yields `lease-valid-unpinned`; stale time yields `lease-expired` regardless of pins.
- Any source decision, manifest, gate, projection, or digest drift fails closed.
- Lease carries only digests, plan id, and numeric times; no prompt, action, event body, secret, or provider output.

---

### Task 1: Lease schema and issue path (RED first)

**Files:**
- Create: `components/northstar-agent-interop/evidence_readiness_lease.py`
- Create: `components/northstar-agent-interop/tests/test_evidence_readiness_lease.py`

**Interfaces:**
- `EvidenceReadinessLease.to_dict()/from_dict()`
- `issue_readiness_lease(decision, manifest, projections, *, now, ttl, expected_decision_digest, expected_manifest_digest, expected_gate_digest) -> EvidenceReadinessLease`

- [x] Test strict canonical lease wire form, exact source bindings, deterministic digest, and no raw action/prompt data.
- [x] Test only fully pinned `ready` decisions issue leases; blocked, unknown, and unpinned decisions fail closed.
- [x] Run focused tests RED before implementation.

### Task 2: Replay verification and expiration

**Files:**
- Modify: `components/northstar-agent-interop/evidence_readiness_lease.py`
- Modify: `components/northstar-agent-interop/tests/test_evidence_readiness_lease.py`

**Interfaces:**
- `verify_readiness_lease(lease, decision, manifest, projections, *, now, expected_decision_digest, expected_manifest_digest, expected_gate_digest, expected_lease_digest=None) -> LeaseVerdict`

- [x] Reparse/replay source decision and reject drifted decision/manifest/gate/projection/digest bindings.
- [x] Return `lease-valid` for an active externally pinned lease, `lease-valid-unpinned` without external lease pin, and `lease-expired` after expiry.
- [x] Preserve `execution_authorized=False` in every state.
- [x] Reject invalid time/TTL, malformed wire, and altered lease fields.

### Task 3: Documentation and local regression

**Files:**
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`
- Create: `docs/superpowers/plans/2026-09-15-evidence-readiness-lease.md`

- [x] Document freshness vs authorization and injected-time limitations.
- [x] Run focused tests, full Interop regression, `py_compile`, `git diff --check`, and sensitive scan.
- [x] Commit locally only; do not notify other sessions or push.
