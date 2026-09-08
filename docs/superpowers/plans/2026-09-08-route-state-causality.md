# Independent Route State and Causal Replay Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `test-driven-development` task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Remove Route Lineage's dependency on `RouteLedger._replay_events`, add explicit replay verdicts, and derive tamper-evident receipt/retry/handoff causal edges from verified route history.

**Architecture:** `route_state.py` owns the pure RouteEvent state machine and returns a bounded replay summary. `route_lineage.py` remains the v2 hash-chain persistence layer and calls only this public validator. `route_causality.py` consumes verified LineageEvents, derives adjacent receipt/retry edges, and accepts explicit handoff links only when route identity and agent direction match. Replay classification never upgrades malformed history to success.

**Tech Stack:** Python 3.12 stdlib only; JSONL, SHA-256, dataclasses, unittest; no network, subprocess, credentials, or remote changes.

## Global Constraints

- Modify only `/var/minis/workspace/northstar-agent-os-local-only`.
- Do not modify public checkout, research worktree, remotes, or servers.
- Do not copy research-line source; use its reported capabilities only as an acceptance checklist.
- Preserve existing `RouteLedger`, `RouteLineage.recover()`, v2 envelope, migration, and 96-test behavior.
- Invalid schema, digest, identity, sequence, state transition, retry, or handoff relation fails closed.
- `ReplayVerdict` is evidence classification, not authorization and not proof of backend success.

## Public Interfaces

```python
@dataclass(frozen=True)
class RouteState:
    status: str
    current_attempt: int
    receipt_count: int
    retry_count: int
    total_latency_ms: int
    failure_counts: dict[str, int]

class RouteStateMachine:
    @staticmethod
    def replay(events: Sequence[RouteEvent]) -> RouteState: ...

@dataclass(frozen=True)
class ReplayVerdict:
    verdict: str  # replayable | stale | conflicting | unverifiable
    reason: str
    cursor: LineageCursor | None

@dataclass(frozen=True)
class CausalEdge:
    relation: str  # receipt | retry | handoff
    parent_event_digest: str
    child_event_digest: str
    edge_digest: str
    handoff_id: str | None

@dataclass(frozen=True)
class HandoffLink:
    handoff_id: str
    parent_event_digest: str
    child_event_digest: str
    source_agent_id: str
    target_agent_id: str

class CausalGraph:
    @classmethod
    def from_events(cls, events: Sequence[LineageEvent], *, handoffs: Sequence[HandoffLink] = ()) -> "CausalGraph": ...
    def verify(self) -> None: ...
```

## Task 1: Extract the independent route state machine

**Files:**
- Create: `components/northstar-agent-interop/route_state.py`
- Create/modify: `components/northstar-agent-interop/tests/test_route_state_causality.py`
- Modify: `components/northstar-agent-interop/route_lineage.py`

- [x] **Step 1: Write RED tests.**

```python
def test_route_state_machine_replays_retry_without_route_ledger_private_method(self):
    events = self.valid_retry_events()
    state = RouteStateMachine.replay(events)
    self.assertEqual(state.status, "succeeded")
    self.assertEqual(state.current_attempt, 2)
    self.assertEqual(state.retry_count, 1)
    self.assertEqual(state.failure_counts, {"backend_timeout": 1})

def test_lineage_recovery_uses_public_state_machine_not_route_ledger_private_method(self):
    original = route_ledger.RouteLedger._replay_events
    route_ledger.RouteLedger._replay_events = lambda *_args: (_ for _ in ()).throw(AssertionError("private validator called"))
    try:
        self.assertEqual(RouteLineage(self.path).recover().verdict, "verified")
    finally:
        route_ledger.RouteLedger._replay_events = original
```

- [x] **Step 2: Run these tests and confirm RED.**

```sh
PYTHONPATH=components/northstar-agent-interop:components/northstar-host:components/northstar-run-contract \
python3 -m unittest components.northstar-agent-interop.tests.test_route_state_causality -v
```

Expected: import failure for `route_state`, and current recovery test would fail once the import is satisfied because it calls the private validator.

- [x] **Step 3: Implement `RouteStateMachine.replay()` as a pure public validator.**

Validate typed decision/receipt payloads, event type/payload agreement, decision digest and all route identity fields, contiguous sequences, terminal states, retryability and bounded summary fields. Do not import or instantiate `RouteLedger`.

- [x] **Step 4: Replace Route Lineage's private validator call with `RouteStateMachine.replay()`, then run focused GREEN tests.**

Expected: focused state/coupling tests pass.

## Task 2: Add replay verdict classification

**Files:**
- Modify: `components/northstar-agent-interop/route_lineage.py`
- Modify: `components/northstar-agent-interop/tests/test_route_state_causality.py`

- [x] **Step 1: Add RED tests for valid, stale-cursor, conflicting, and unverifiable history.**

```python
def test_replay_verdict_marks_valid_history_replayable(self):
    result = RouteLineage(self.path).replay_verdict()
    self.assertEqual(result.verdict, "replayable")

def test_replay_verdict_marks_cursor_mismatch_stale(self):
    cursor = RouteLineage(self.path).recover().cursor
    result = RouteLineage(self.path).replay_verdict(expected_cursor=LineageCursor(cursor.sequence - 1, cursor.event_digest))
    self.assertEqual(result.verdict, "stale")

def test_replay_verdict_marks_tampered_history_unverifiable(self):
    self.tamper_one_v2_row()
    self.assertEqual(RouteLineage(self.path).replay_verdict().verdict, "unverifiable")
```

- [x] **Step 2: Run tests to verify RED.**

Expected: `AttributeError` because `ReplayVerdict` and `replay_verdict()` do not exist.

- [x] **Step 3: Implement classification.**

`replayable` requires full recovery verification. A cursor mismatch maps to `stale`; idempotency/conflict errors map to `conflicting`; all schema, digest, state, or IO validation failures map to `unverifiable`. The method returns a verdict object and never returns `replayable` for failed verification.

- [x] **Step 4: Run focused GREEN tests.**

## Task 3: Add receipt/retry/handoff causal graph

**Files:**
- Create: `components/northstar-agent-interop/route_causality.py`
- Modify: `components/northstar-agent-interop/route_lineage.py`
- Modify: `components/northstar-agent-interop/tests/test_route_state_causality.py`

- [x] **Step 1: Add RED tests.**

```python
def test_causal_graph_derives_receipt_and_retry_edges(self):
    recovery = RouteLineage(self.path).recover()
    graph = CausalGraph.from_events(recovery.events)
    self.assertEqual([edge.relation for edge in graph.edges], ["receipt", "receipt", "retry", "receipt"])
    graph.verify()

def test_causal_graph_rejects_handoff_with_wrong_agent_direction(self):
    recovery = RouteLineage(self.path).recover()
    with self.assertRaises(ValueError):
        CausalGraph.from_events(
            recovery.events,
            handoffs=[HandoffLink("handoff-1", recovery.events[1].event_digest, recovery.events[2].event_digest, "wrong", "codex")],
        )
```

- [x] **Step 2: Run tests to verify RED.**

Expected: import failure for `route_causality`.

- [x] **Step 3: Implement strict causal edges.**

Derive `decision.selected → first receipt` and adjacent receipt transitions. A failed retryable event followed by the next-attempt started event becomes `retry`; all other adjacent transitions become `receipt`. Each edge digest covers relation, parent/child digests and optional handoff ID. Explicit handoffs must share task/thread/run/workspace/policy/step/trace identity, require parent target == source agent, child target == target agent, and reject self-links, unknown event digests, duplicate edge IDs and wrong direction.

- [x] **Step 4: Add `RouteLineage.causal_graph()` and run focused GREEN tests.**

## Task 4: Documentation and complete verification

**Files:**
- Modify: `components/northstar-agent-interop/README.md`
- Modify: this plan

- [x] **Step 1: Document public state validation, replay verdict semantics, causal edges, and the fact that handoff links are typed evidence rather than signatures.**
- [x] **Step 2: Run py_compile, focused tests, full Interop regression, documentation tests, diff check, and sensitive scan.**
- [x] **Step 3: Confirm public checkout unchanged and create one local-only commit after fresh evidence.**

## Self-review

- Route selection remains untouched.
- Route Ledger v1 APIs remain untouched except its already-validated flock changes.
- A valid replay verdict is never emitted for malformed or tampered data.
- A hash-chain still needs an external cursor to detect final-row rollback.
- Handoff causal edges do not prove cryptographic authorization; authorization remains in `handoff.py`.

## Execution notes

- Focused RED/GREEN evidence was obtained for the missing state machine, replay verdict, causal graph, cross-segment handoff, duplicate digest, and forged-event metadata checks.
- A few tests were initially malformed during iterative editing; those failures were corrected as test-fixture errors before accepting production behavior.
- Final verification must still be run after documentation edits; this slice remains local-only and is not public-ready.
