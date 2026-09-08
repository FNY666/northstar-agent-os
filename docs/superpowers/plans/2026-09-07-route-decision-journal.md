# RouteDecision Journal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an independent, replayable and idempotent journal around deterministic BackendRouter decisions without changing the public checkout or the existing local-only Router.

**Architecture:** The journal is an additive research-layer component. It records a canonical request digest, candidate snapshot, decision or structured routing failure, policy revision, deadline narrowing, and an idempotency key in append-only JSONL. A replay function recomputes the decision from a supplied router and compares the canonical decision fingerprint; it never executes a backend. Duplicate idempotency keys return the same receipt only when the canonical input matches, otherwise fail closed.

**Tech Stack:** Python 3.10+, standard library, JSONL with `fsync`, `hashlib`, `unittest`, existing Interop contracts copied from the latest public `main` only as read-only imports.

## Global Constraints

- This worktree is an independent research line; do not modify `/var/minis/workspace/northstar-agent-os` or `/var/minis/workspace/northstar-agent-os-local-only`.
- Do not cherry-pick, merge, push, or create a PR from this slice.
- Do not install, authenticate, or execute real Codex, Claude Code, Cursor, Hermes, or OpenBot backends.
- A route decision is selection metadata, not authorization; Handoff verification remains a separate gate.
- Unknown, stale, malformed, conflicting, or non-replayable journal entries fail closed.
- Journal records must not contain prompts, secrets, raw tool output, or opaque context contents.

---

### Task 1: Canonical journal schema and RED tests

**Files:**
- Create: `components/northstar-agent-interop/route_journal.py`
- Create: `components/northstar-agent-interop/tests/test_route_journal.py`

**Interfaces:**
- `RouteJournalRecord.from_dict(value) -> RouteJournalRecord`
- `RouteJournalRecord.to_dict() -> dict[str, object]`
- `RouteJournalRecord.canonical_json() -> bytes`
- `decision_fingerprint(record) -> str`

- [ ] Write tests for required fields, unknown-field rejection, stable canonical serialization, no prompt/raw output fields, and decision fingerprint changes when selected agent or deadline changes.
- [ ] Run `PYTHONPATH=. python -m unittest discover -s tests -p 'test_route_journal.py' -v` and observe RED because the module does not exist.
- [ ] Implement strict dataclasses for request digest, candidate snapshot, decision status (`selected|failed`), failure class, selected identity, narrowed deadline, policy revision, and idempotency key.
- [ ] Re-run the focused tests to GREEN.

### Task 2: Append-only fsync journal and idempotency

**Files:**
- Modify: `components/northstar-agent-interop/route_journal.py`
- Modify: `components/northstar-agent-interop/tests/test_route_journal.py`

**Interfaces:**
- `RouteDecisionJournal(path).append(record) -> RouteJournalRecord`
- `RouteDecisionJournal(path).read() -> Iterator[RouteJournalRecord]`
- `RouteDecisionJournal(path).get_by_idempotency(key) -> RouteJournalRecord | None`

- [ ] Add RED tests for fsync append, truncated final-line skip, duplicate identical idempotency replay, and conflicting duplicate rejection.
- [ ] Implement parent-directory creation with restrictive permissions, append+flush+fsync, and tolerant truncated-tail reading.
- [ ] Ensure duplicate records are returned without a second append and conflicting canonical input raises a typed journal conflict.
- [ ] Re-run focused journal tests and confirm GREEN.

### Task 3: Router decision capture and replay

**Files:**
- Modify: `components/northstar-agent-interop/route_journal.py`
- Create: `components/northstar-agent-interop/tests/test_route_journal_integration.py`

**Interfaces:**
- `record_route(journal, router, request, *, now, policy_revision, idempotency_key) -> RouteJournalRecord`
- `replay_route(journal, router, record, *, now) -> RouteJournalRecord`

- [ ] Write RED integration tests with deterministic fake backend specs for capability filtering, disabled/health/cooldown rejection, preferred-agent soft fallback, stable priority tie-break, deadline narrowing, route/Handoff identity matching, and structured failure classes.
- [ ] Implement an adapter protocol shim that calls the existing router without importing the local-only worktree; the journal records only sanitized candidate metadata and the RouteDecision result.
- [ ] Implement replay comparison that rejects changed candidate snapshots, policy revision, request digest, or decision fingerprint.
- [ ] Verify replay does not invoke a backend adapter or mutate an external system.

### Task 4: Independent evaluation and handoff boundary review

**Files:**
- Modify: `components/northstar-agent-interop/route_journal.py`
- Modify: `components/northstar-agent-interop/tests/test_route_journal_integration.py`
- Create: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`

- [ ] Add tests proving a journal-selected identity cannot authorize a mismatched Handoff Grant and a route deadline cannot widen an existing handoff deadline.
- [ ] Add tests for route failure vs adapter execution failure classification and redacted structured error metadata.
- [ ] Document what the journal proves, what it cannot prove, replay assumptions, and why it remains a local research candidate.
- [ ] Run compile, diff check, sensitive scan, and complete Interop suite.

### Task 5: Research acceptance gate

- [ ] Run `python -m py_compile` over all changed Python files.
- [ ] Run `PYTHONPATH=.:../northstar-host:../northstar-run-contract python -m unittest discover -s tests -p 'test_*.py' -v`.
- [ ] Run the existing Interop baseline tests plus the journal tests and confirm no public or local-only worktree was changed.
- [ ] Create a local research commit only after all evidence is fresh; do not push or create a PR.
- [ ] Send a cross-session handoff containing commit, diff, test counts, limitations, and explicit no-public-integration status.

## Expected research outcome

This slice is a candidate for a future complete capability generation only if it demonstrates deterministic replay, idempotency, fail-closed conflict handling, and clean separation between routing selection, authorization, backend execution, and independent verification. Passing unit tests alone is not sufficient evidence for public release.
