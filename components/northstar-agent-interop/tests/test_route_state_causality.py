import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(COMPONENT_ROOT))

import route_ledger
from backend_router import RouteDecision
from route_ledger import RouteEvent, RouteLedger, RouteReceipt
from route_lineage import LineageCursor, LineageEvent, ReplayVerdict, RouteLineage
from route_state import RouteStateMachine
from route_causality import CausalGraph, HandoffLink


DECISION = RouteDecision.from_dict(
    {
        "schema_version": "northstar.route-decision.v1",
        "route_id": "route-causal-001",
        "task_id": "task-causal-001",
        "thread_id": "thread-causal-001",
        "run_id": "run-causal-001",
        "actor_id": "actor-causal-001",
        "workspace_id": "workspace-causal-001",
        "policy_revision": "policy-causal-1",
        "step_id": "causal",
        "trace_id": "trace-causal-001",
        "input_digest": "sha256:" + "3" * 64,
        "requested_capabilities": ["workspace:read"],
        "deadline_at": 3_900,
        "target_agent_id": "codex",
        "provider": "openai",
        "backend_version": "cli-v1",
        "priority": 10,
        "selected_at": 3_001,
    }
)


def receipt_event(*, status, attempt, key, recorded_at, sequence, retryable=False, failure_class=None, error_code=None):
    receipt = RouteReceipt.from_decision(
        DECISION,
        status=status,
        attempt=attempt,
        latency_ms=10 if status == "started" else 20,
        failure_class=failure_class,
        error_code=error_code,
        retryable=retryable,
        idempotency_key=key,
        recorded_at=recorded_at,
    )
    return RouteEvent.from_receipt(receipt, sequence=sequence)


def valid_retry_events():
    return [
        RouteEvent.from_decision(
            DECISION,
            event_type="decision.selected",
            attempt=1,
            idempotency_key="causal-selected-1",
            recorded_at=3_001,
        ),
        receipt_event(status="started", attempt=1, key="causal-started-1", recorded_at=3_002, sequence=2),
        receipt_event(
            status="failed",
            attempt=1,
            key="causal-failed-1",
            recorded_at=3_003,
            sequence=3,
            retryable=True,
            failure_class="backend_timeout",
            error_code="timeout",
        ),
        receipt_event(status="started", attempt=2, key="causal-started-2", recorded_at=3_004, sequence=4),
        receipt_event(status="succeeded", attempt=2, key="causal-succeeded-2", recorded_at=3_005, sequence=5),
    ]


def valid_child_events():
    child_decision = RouteDecision.from_dict(
        {
            **DECISION.to_dict(),
            "route_id": "route-causal-child-001",
            "step_id": "child",
            "target_agent_id": "hermes",
            "provider": "local",
            "backend_version": "agent-v2",
        }
    )
    return [
        RouteEvent.from_decision(
            child_decision,
            event_type="decision.selected",
            attempt=1,
            idempotency_key="child-selected-1",
            recorded_at=3_100,
        ),
        RouteEvent.from_receipt(
            RouteReceipt.from_decision(
                child_decision,
                status="started",
                attempt=1,
                latency_ms=8,
                failure_class=None,
                error_code=None,
                retryable=False,
                idempotency_key="child-started-1",
                recorded_at=3_101,
            ),
            sequence=2,
        ),
        RouteEvent.from_receipt(
            RouteReceipt.from_decision(
                child_decision,
                status="succeeded",
                attempt=1,
                latency_ms=18,
                failure_class=None,
                error_code=None,
                retryable=False,
                idempotency_key="child-succeeded-1",
                recorded_at=3_102,
            ),
            sequence=3,
        ),
    ]


def write_events(lineage, events):
    for event in events:
        lineage.append(event)


class RouteStateMachineTests(unittest.TestCase):
    def test_route_state_machine_replays_retry_without_route_ledger_private_method(self):
        state = RouteStateMachine.replay(valid_retry_events())
        self.assertEqual(state.status, "succeeded")
        self.assertEqual(state.current_attempt, 2)
        self.assertEqual(state.retry_count, 1)
        self.assertEqual(state.failure_counts, {"backend_timeout": 1})

    def test_route_state_machine_rejects_forged_event_metadata(self):
        events = valid_retry_events()
        forged = replace(events[1], payload_digest="sha256:" + "f" * 64)
        with self.assertRaises(ValueError):
            RouteStateMachine.replay([events[0], forged, *events[2:]])


        with tempfile.TemporaryDirectory() as directory:
            ledger_path = Path(directory) / "route-ledger.jsonl"
            lineage_path = Path(directory) / "lineage.jsonl"
            ledger = RouteLedger(ledger_path)
            events = valid_retry_events()
            for event in events:
                if event.event_type == "decision.selected":
                    ledger.append_decision(
                        DECISION,
                        attempt=event.attempt,
                        idempotency_key=event.idempotency_key,
                        recorded_at=event.recorded_at,
                    )
                else:
                    ledger.append_receipt(RouteReceipt.from_dict(event.payload["receipt"]))
            lineage = RouteLineage(lineage_path)
            for event in events:
                lineage.append(event)
            original = route_ledger.RouteLedger._replay_events
            route_ledger.RouteLedger._replay_events = lambda *_args: (_ for _ in ()).throw(
                AssertionError("private validator called")
            )
            try:
                self.assertEqual(lineage.recover().verdict, "verified")
            finally:
                route_ledger.RouteLedger._replay_events = original

    def test_route_lineage_empty_history_remains_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            recovery = RouteLineage(Path(directory) / "empty.jsonl").recover()
            self.assertEqual(recovery.verdict, "verified")
            self.assertEqual(recovery.events, ())


class ReplayVerdictTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tempdir.name) / "lineage.jsonl"
        self.lineage = RouteLineage(self.path)
        write_events(self.lineage, valid_retry_events())

    def tearDown(self):
        self.tempdir.cleanup()

    def test_replay_verdict_marks_valid_history_replayable(self):
        result = self.lineage.replay_verdict()
        self.assertIsInstance(result, ReplayVerdict)
        self.assertEqual(result.verdict, "replayable")
        self.assertEqual(result.reason, "verified")

    def test_replay_verdict_marks_cursor_mismatch_stale(self):
        cursor = self.lineage.recover().cursor
        assert cursor is not None
        stale = LineageCursor(cursor.sequence - 1, cursor.event_digest)
        result = self.lineage.replay_verdict(expected_cursor=stale)
        self.assertEqual(result.verdict, "stale")

    def test_replay_verdict_marks_tampered_history_unverifiable(self):
        rows = self.path.read_text(encoding="utf-8").splitlines()
        row = rows[1].replace("causal-started-1", "causal-started-tampered")
        self.path.write_text("\n".join((rows[0], row, *rows[2:])) + "\n", encoding="utf-8")
        result = RouteLineage(self.path).replay_verdict()
        self.assertEqual(result.verdict, "unverifiable")


class CausalGraphTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tempdir.name) / "lineage.jsonl"
        self.lineage = RouteLineage(self.path)
        write_events(self.lineage, valid_retry_events())
        self.events = self.lineage.recover().events

    def child_events(self):
        child = valid_child_events()
        child_path = Path(self.tempdir.name) / "child-lineage.jsonl"
        child_lineage = RouteLineage(child_path)
        write_events(child_lineage, child)
        events = child_lineage.recover().events
        child_lineage = None
        return events

    def tearDown(self):
        self.tempdir.cleanup()

    def test_causal_graph_derives_receipt_and_retry_edges(self):
        graph = CausalGraph.from_events(self.events)
        self.assertEqual(
            [edge.relation for edge in graph.edges],
            ["receipt", "receipt", "retry", "receipt"],
        )
        graph.verify()

    def test_lineage_exposes_verified_causal_graph(self):
        graph = self.lineage.causal_graph()
        self.assertIsInstance(graph, CausalGraph)
        self.assertEqual(len(graph.edges), 4)
        graph.verify()

    def test_causal_graph_rejects_handoff_with_wrong_agent_direction(self):
        with self.assertRaises(ValueError):
            CausalGraph.from_events(
                self.events,
                handoffs=[
                    HandoffLink(
                        "handoff-1",
                        self.events[1].event_digest,
                        self.events[2].event_digest,
                        "wrong",
                        "codex",
                    )
                ],
            )

    def test_causal_graph_rejects_nonterminal_handoff_parent(self):
        child_events = self.child_events()
        with self.assertRaises(ValueError):
            CausalGraph.from_segments(
                (self.events, child_events),
                handoffs=[
                    HandoffLink(
                        "handoff-2",
                        self.events[1].event_digest,
                        child_events[0].event_digest,
                        "codex",
                        "hermes",
                    )
                ],
            )

    def test_causal_graph_connects_verified_route_segments_with_handoff(self):
        child_events = self.child_events()
        link = HandoffLink(
            "handoff-1",
            self.events[-1].event_digest,
            child_events[0].event_digest,
            "codex",
            "hermes",
        )
        graph = CausalGraph.from_segments((self.events, child_events), handoffs=(link,))
        self.assertEqual(graph.edges[-1].relation, "handoff")
        graph.verify()

    def test_causal_graph_rejects_duplicate_event_digest_across_segments(self):
        with self.assertRaises(ValueError):
            CausalGraph.from_segments(((self.events[0],), (self.events[0],)))
