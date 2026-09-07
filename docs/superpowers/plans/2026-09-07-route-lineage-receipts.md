# Route Ledger Lineage and Receipt Lifecycle Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or **superpowers:executing-plans** to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an independent causal lineage and receipt consistency layer to the Route Ledger research line without changing Router selection, authorization, or any public/local-only worktree.

**Architecture:** A typed append-only lifecycle sits above journal decisions. It links route decision, retry attempts, Handoff identity, dispatch receipt, backend outcome, replay, and supersession through bounded opaque IDs and digests. A verifier checks legal transitions, retry narrowing, and receipt/decision consistency; it never executes a backend and never grants authorization.

**Tech Stack:** Python 3.10+, standard library, dataclasses, Literal/Enum, hashlib, unittest.

## Global Constraints

- Work only in `/var/minis/workspace/northstar-agent-os-research-journal`.
- No public checkout or local-only worktree writes.
- No push, PR, cherry-pick, or merge.
- No real backend execution or credentials.
- Lifecycle evidence is not authorization; Handoff/Host gates remain authoritative.
- Retry can only narrow or preserve capability, deadline, and target identity.

---

### Task 1: Receipt lifecycle schema and RED tests

**Files:**
- Create: `components/northstar-agent-interop/route_lineage.py`
- Create: `components/northstar-agent-interop/tests/test_route_lineage.py`

**Interfaces:**
- `ReceiptStatus = Literal["planned", "dispatched", "succeeded", "failed", "replayed", "superseded"]`
- `RouteLineageEvent.from_dict(value) -> RouteLineageEvent`
- `RouteLineageEvent.to_dict() -> dict[str, object]`
- `LineageGraph.append(event) -> RouteLineageEvent`
- `LineageGraph.read() -> Iterator[RouteLineageEvent]`

- [ ] Write RED tests for strict fields, unknown-field rejection, bounded IDs, no raw prompt/output, legal initial status, and illegal terminal transitions.
- [ ] Implement typed lifecycle events with `event_id`, `route_id`, `parent_event_id`, `receipt_id`, `status`, `target_agent_id`, `provider`, `capabilities`, `deadline_at`, `payload_digest`, and `decision_fingerprint`.
- [ ] Enforce append-only fsync and sequence continuity.

### Task 2: Retry narrowing and causal graph

**Files:**
- Modify: `components/northstar-agent-interop/route_lineage.py`
- Modify: `components/northstar-agent-interop/tests/test_route_lineage.py`

**Interfaces:**
- `derive_retry(parent, *, event_id, receipt_id, deadline_at, capabilities) -> RouteLineageEvent`
- `causal_chain(graph, terminal_event_id) -> tuple[RouteLineageEvent, ...]`

- [ ] Test retry from retryable vs non-retryable failures.
- [ ] Test retries cannot change target/provider, widen deadline, or add capabilities.
- [ ] Test lineage traversal rejects missing parent, cycles, and cross-route parent events.
- [ ] Implement retry derivation and causal traversal with bounded depth.

### Task 3: Independent receipt consistency verifier

**Files:**
- Modify: `components/northstar-agent-interop/route_lineage.py`
- Create: `components/northstar-agent-interop/tests/test_route_lineage_integration.py`

**Interfaces:**
- `verify_lineage(graph, *, route_record, handoff, max_events=256) -> VerificationResult`
- `VerificationResult(verdict: Literal["verified", "failed", "unknown"], reasons: tuple[str, ...])`

- [ ] Test verified success requires matching route decision identity/fingerprint, Handoff identity/deadline/capabilities, and receipt payload digest.
- [ ] Test failed backend receipt cannot become success by replay or retry without a new planned event.
- [ ] Test unknown/missing evidence returns `unknown`, never success.
- [ ] Test superseded parent cannot be treated as the current terminal attempt.
- [ ] Implement independent checks without calling any router or backend.

### Task 4: Research boundary and full regression

**Files:**
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`
- Modify: `components/northstar-agent-interop/tests/test_route_journal_integration.py`

- [ ] Document lineage as evidence, not authorization; explain retry narrowing and terminal semantics.
- [ ] Run all existing Interop tests plus lineage tests.
- [ ] Run compile, diff check, sensitive scan, and one rollback-to-red guard for terminal transition enforcement.
- [ ] Commit only on `research-route-journal`; hand off commit and evidence for comparison. Do not push.
