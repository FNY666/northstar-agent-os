# Route Ledger Replay and Migration Research Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the independent RouteDecision Journal into a version-aware replay and lineage layer that distinguishes replayable, stale, conflicting, and unverifiable decisions across restarts and schema migrations.

**Architecture:** Keep the existing journal append-only and add a migration/replay verdict layer rather than mutating historical records. A versioned migration registry transforms old canonical records into the current in-memory model only when the transformation is lossless and explicitly registered. Replay returns a typed verdict and lineage metadata; it never executes a backend or treats a migrated record as fresh authorization.

**Tech Stack:** Python 3.10+, standard library, JSONL, `fcntl.flock`, `hashlib`, `unittest`.

## Global Constraints

- Work only in `/var/minis/workspace/northstar-agent-os-research-journal`.
- Do not modify `/var/minis/workspace/northstar-agent-os-local-only` or the public checkout.
- Do not push, cherry-pick, merge, or create a PR.
- Do not run real backends or use credentials.
- Historical records are immutable; migration creates an in-memory view or an explicit migration event, never overwrites source JSONL.
- Replay verdict is not authorization and cannot bypass Handoff/Host policy.

---

### Task 1: Typed replay verdict and lineage RED tests

**Files:**
- Create: `components/northstar-agent-interop/route_replay.py`
- Create: `components/northstar-agent-interop/tests/test_route_replay.py`

**Interfaces:**
- `ReplayVerdict`: `replayable | stale | conflicting | unverifiable`
- `ReplayLineage(parent_id, attempt, receipt_id, cause)`
- `ReplayResult(verdict, record, lineage, reason)`
- `classify_replay(record, current_snapshot, current_policy_revision, *, request_digest, lineage) -> ReplayResult`

- [ ] Write RED tests for exact match → replayable, candidate change → stale, digest mismatch → conflicting, missing required evidence → unverifiable, and retry lineage preservation.
- [ ] Implement strict dataclasses with Literal aliases, bounded IDs, and no raw prompt/output fields.
- [ ] Run focused tests to GREEN.

### Task 2: Immutable schema migration registry

**Files:**
- Modify: `components/northstar-agent-interop/route_replay.py`
- Create: `components/northstar-agent-interop/tests/test_route_migration.py`

**Interfaces:**
- `MigrationRegistry.register(source_version, target_version, transform)`
- `MigrationRegistry.migrate(raw_record) -> (migrated_record, migration_chain)`
- `MigrationError`

- [ ] Add RED tests for one registered lossless migration, unknown source version, missing fields, transformation that drops decision identity, and migration chain digest.
- [ ] Implement explicit version graph traversal with cycle detection and canonical migration-chain digest.
- [ ] Never rewrite the source record and never upgrade an authorization claim.

### Task 3: Crash cursor and lineage recovery

**Files:**
- Modify: `components/northstar-agent-interop/route_replay.py`
- Create: `components/northstar-agent-interop/tests/test_route_recovery.py`

**Interfaces:**
- `RecoveryCursor(sequence, file_offset, last_idempotency_key, digest)`
- `recover_cursor(path) -> RecoveryCursor`
- `lineage_for_retry(parent_record, *, retry_idempotency_key, receipt_id) -> ReplayLineage`

- [ ] Test restart after a complete line, truncated final line, duplicate retry, conflicting retry, and cursor digest mismatch.
- [ ] Implement read-only cursor recovery that ignores only the truncated final line and rejects complete corruption.
- [ ] Ensure retry lineage points to the original decision and never silently widens deadline or capability.

### Task 4: Integration and independent review

**Files:**
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`
- Modify: `components/northstar-agent-interop/tests/test_route_journal_integration.py`

- [ ] Add tests connecting journal records, migration, replay verdict, retry lineage, and Handoff compatibility.
- [ ] Document replay assumptions, migration limits, crash-recovery boundaries, and the distinction between evidence and authorization.
- [ ] Run the complete Interop suite, compile, diff check, and sensitive scan.

### Acceptance

- Existing research baseline plus new tests all pass.
- At least one deliberate guard rollback turns a replay/migration test red.
- No public or local-only worktree changes.
- Commit remains on `research-route-journal` only and is handed off for generation comparison.
