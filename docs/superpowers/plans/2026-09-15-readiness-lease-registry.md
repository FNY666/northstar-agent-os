# Evidence Readiness Lease Registry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or **superpowers:executing-plans** to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Persist the lifecycle of an evidence-readiness lease so revocation and restart recovery cannot be bypassed by reusing an otherwise valid lease object.

**Architecture:** `EvidenceReadinessLeaseRegistry` records `registered` and `revoked` events in a canonical, fsynced, hash-chained JSONL log protected by same-host `flock`. Register is idempotent for the same lease digest and rejects conflicting metadata; revoke appends a durable tombstone. `inspect` derives `active`, `expired`, `revoked`, `unknown`, or `unverifiable` without authorizing execution.

**Tech Stack:** Python 3.10+, standard library, existing `EvidenceReadinessLease`, `unittest`. No network and no new dependency.

## Global Constraints

- Research worktree only; no local-only, main, integration-next, arena, runtime, merge, cherry-pick, or remote push changes.
- Lease lifecycle is evidence freshness state, not permission or action authorization.
- Registry records contain lease and digest metadata only; no prompt, action, event body, secret, or provider output.
- Same-host `flock` protects read/check/append; no cross-host exactly-once claim.
- Complete corruption, chain breaks, and missing history after first registration are `unverifiable` and block mutation.
- Revocation is monotonic; a revoked lease cannot become active again.

---

### Task 1: Durable registration and inspection (RED first)

**Files:**
- Create: `components/northstar-agent-interop/evidence_readiness_lease_registry.py`
- Create: `components/northstar-agent-interop/tests/test_evidence_readiness_lease_registry.py`

**Interfaces:**
- `LeaseRegistryRecord.to_dict()/from_dict()`
- `EvidenceReadinessLeaseRegistry(root)`
- `register(lease) -> LeaseRegistryRecord`
- `inspect(lease_digest, *, now) -> LeaseRegistryVerdict`

- [x] Test registration, idempotent duplicate registration, restart recovery, and active/expired/unknown states.
- [x] Test complete schema, digest, lease binding, and no raw sensitive fields.
- [x] Run focused tests RED before implementation.

### Task 2: Durable revocation and fail-closed recovery

**Files:**
- Modify: `components/northstar-agent-interop/evidence_readiness_lease_registry.py`
- Modify: `components/northstar-agent-interop/tests/test_evidence_readiness_lease_registry.py`

- [x] Revoke an active lease and preserve revoked state after restart.
- [x] Reject duplicate/conflicting registration, repeated revocation, and revocation of unknown leases.
- [x] Detect truncated tail, complete malformed line, tampering, reordering, and missing history.
- [x] Ensure revocation is monotonic and execution authorization is always false.

### Task 3: Documentation and local regression

**Files:**
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`
- Create: `docs/superpowers/plans/2026-09-15-readiness-lease-registry.md`

- [x] Document lease lifecycle, revocation monotonicity, same-host locking, and freshness-vs-authorization boundaries.
- [x] Run focused tests, full Interop regression, `py_compile`, `git diff --check`, and sensitive scan.
- [x] Commit locally only; do not notify other sessions or push.
