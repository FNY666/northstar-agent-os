# Transactional Lineage Append Research Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or **superpowers:executing-plans** to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bind lease, cursor, and lineage event append into one crash-aware local transaction boundary.

**Architecture:** A transactional append coordinator holds the lineage lock, validates the owner/fencing token and expected cursor, writes the event, fsyncs the event file, then atomically persists the next cursor/lease checkpoint. Recovery compares the checkpoint against the last event hash and sequence. It never claims distributed consensus or remote durability.

**Tech Stack:** Python 3.10+, standard library, JSONL, `fcntl.flock`, atomic replace, fsync, unittest.

## Global Constraints

- Research worktree only: `/var/minis/workspace/northstar-agent-os-research-journal`.
- No public checkout or local-only Router modifications.
- No push, PR, merge, or cherry-pick.
- No real backend execution or credentials.
- A committed event is evidence, not authorization.
- Fail closed on checkpoint mismatch, stale lease, partial transaction, or duplicate terminal receipt.

---

### Task 1: Transaction checkpoint contract and RED tests

**Files:**
- Create: `components/northstar-agent-interop/lineage_transaction.py`
- Create: `components/northstar-agent-interop/tests/test_lineage_transaction.py`

**Interfaces:**
- `TransactionCheckpoint.from_dict(value) -> TransactionCheckpoint`
- `TransactionalLineageStore.append(event, cursor, lease, now) -> RecoveryCursor`
- `TransactionalLineageStore.recover() -> (RecoveryCursor, Lease | None)`

- [ ] Write RED tests for strict checkpoint fields, expected cursor mismatch, stale lease, duplicate terminal receipt, and successful append ordering.
- [ ] Implement canonical checkpoint with sequence, event digest, journal digest, fencing token, owner ID, and transaction state.
- [ ] Ensure unknown fields, raw prompt/output, and invalid digests fail closed.

### Task 2: Crash and recovery simulation

**Files:**
- Modify: `components/northstar-agent-interop/lineage_transaction.py`
- Modify: `components/northstar-agent-interop/tests/test_lineage_transaction.py`

- [ ] Add deterministic fault injection points: before event write, after event fsync, before checkpoint replace, after checkpoint replace.
- [ ] Test recovery outcomes: committed transaction resumes, incomplete transaction becomes `unknown`, stale checkpoint is rejected, and no duplicate terminal event is created.
- [ ] Keep source journal append-only and never delete an event to hide a failed transaction.

### Task 3: Multi-process fencing integration

**Files:**
- Create: `components/northstar-agent-interop/tests/test_lineage_transaction_integration.py`
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`

- [ ] Run two processes racing the same cursor/lease and prove one append wins while the other fails closed.
- [ ] Test restart with a higher fencing token and verify the old owner cannot append.
- [ ] Document limitations: local filesystem atomicity only, no distributed consensus, native Linux validation still required.

### Acceptance

- Existing Interop baseline plus transaction tests pass.
- At least one fault-injection guard is shown RED when bypassed.
- Compile, diff, sensitive scan pass.
- Commit stays in research worktree only; no public integration.
