# Route Recovery Cursor and Fencing Research Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or **superpowers:executing-plans** to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add owner-bound recovery cursors and fencing to the independent lineage research store so restart/resume cannot create duplicate or stale concurrent lineage writers.

**Architecture:** A cursor binds the last trusted sequence, event digest, schema version, and journal path. A lease binds an owner and monotonically increasing fencing token to a bounded expiry. Every append requiring recovery authority checks owner, token, cursor, and current time; expired or stale owners fail closed. This is a local multi-process research control, not a distributed consensus system.

**Tech Stack:** Python 3.10+, standard library, dataclasses, `fcntl.flock`, monotonic/epoch time, `unittest`.

## Global Constraints

- Work only in `/var/minis/workspace/northstar-agent-os-research-journal`.
- Never modify public checkout or `/var/minis/workspace/northstar-agent-os-local-only`.
- No push, PR, merge, or cherry-pick.
- No real backend execution or credentials.
- Lease/fencing is an execution coordination guard, not authorization.
- Fail closed on expired, stale, mismatched, or ambiguous cursor state.

---

### Task 1: Cursor contract and lease RED tests

**Files:**
- Create: `components/northstar-agent-interop/recovery_cursor.py`
- Create: `components/northstar-agent-interop/tests/test_recovery_cursor.py`

**Interfaces:**
- `RecoveryCursor(sequence, event_digest, schema_version, journal_digest)`
- `Lease(owner_id, fencing_token, expires_at)`
- `LeaseManager.acquire(owner_id, now, ttl) -> Lease`
- `LeaseManager.heartbeat(lease, now, ttl) -> Lease`
- `LeaseManager.validate(lease, now) -> None`

- [ ] Write RED tests for invalid cursor digests, sequence gaps, owner mismatch, expiry, stale fencing token, and heartbeat renewal.
- [ ] Implement strict bounded IDs and epoch timestamps; fencing token must increase on each acquisition.
- [ ] Run focused tests to GREEN.

### Task 2: Cursor-bound lineage append

**Files:**
- Modify: `components/northstar-agent-interop/route_lineage.py`
- Modify: `components/northstar-agent-interop/tests/test_route_lineage_persistence.py`

**Interfaces:**
- `LineageGraph.cursor() -> RecoveryCursor`
- `LineageGraph.append_with_lease(event, cursor, lease, now) -> RecoveryCursor`
- `LineageGraph.recover_cursor() -> RecoveryCursor`

- [ ] Add tests for append with current cursor, stale cursor rejection, digest mismatch rejection, expired lease rejection, and fencing token rejection.
- [ ] Bind append to a lease lock and verify cursor before writing; return the next cursor only after fsync.
- [ ] Ensure terminal events are not appended twice under the same idempotency/receipt identity.

### Task 3: Restart and fencing integration

**Files:**
- Create: `components/northstar-agent-interop/tests/test_recovery_integration.py`
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`

- [ ] Test process A writes and heartbeats, process B cannot use A’s lease, expiry allows B to acquire a higher fencing token, and A then fails closed.
- [ ] Test restart recovery from a cursor whose digest matches the last event and reject a manually altered cursor.
- [ ] Test two processes racing append produces one legal sequence with no duplicate terminal receipt.
- [ ] Document local lock/lease limitations: no distributed consensus, no network partition proof, native Linux still required for production.

### Acceptance

- Existing research baseline plus cursor/lease tests pass.
- One deliberate lease/fencing guard rollback turns its test red.
- `py_compile`, `git diff --check`, sensitive scan pass.
- Commit remains local research-only and is handed off for generation comparison; no public integration.
