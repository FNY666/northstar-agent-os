import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMPONENT_ROOT))
sys.path.insert(0, str(COMPONENT_ROOT.parent / "northstar-host"))
sys.path.insert(0, str(COMPONENT_ROOT.parent / "northstar-run-contract"))

from backend_router import RouteDecision  # noqa: E402
from route_causality import CausalEdge, CausalGraph  # noqa: E402
from route_ledger import RouteEvent, RouteReceipt  # noqa: E402
from route_lineage import LineageEvent  # noqa: E402


DECISION = RouteDecision.from_dict(
    {
        "schema_version": "northstar.route-decision.v1",
        "route_id": "route-admission-001",
        "task_id": "task-admission-001",
        "thread_id": "thread-admission-001",
        "run_id": "run-admission-001",
        "actor_id": "actor-admission-001",
        "workspace_id": "workspace-admission-001",
        "policy_revision": "policy-admission-1",
        "step_id": "admission",
        "trace_id": "trace-admission-001",
        "input_digest": "sha256:" + "4" * 64,
        "requested_capabilities": ["workspace:read"],
        "deadline_at": 4_900,
        "target_agent_id": "codex",
        "provider": "openai",
        "backend_version": "cli-v1",
        "priority": 10,
        "selected_at": 4_001,
    }
)


def verified_graph():
    selected = RouteEvent.from_decision(
        DECISION,
        event_type="decision.selected",
        attempt=1,
        idempotency_key="admission-selected-1",
        recorded_at=4_001,
    )
    started = RouteEvent.from_receipt(
        RouteReceipt.from_decision(
            DECISION,
            status="started",
            attempt=1,
            latency_ms=11,
            failure_class=None,
            error_code=None,
            retryable=False,
            idempotency_key="admission-started-1",
            recorded_at=4_002,
        ),
        sequence=2,
    )
    succeeded = RouteEvent.from_receipt(
        RouteReceipt.from_decision(
            DECISION,
            status="succeeded",
            attempt=1,
            latency_ms=21,
            failure_class=None,
            error_code=None,
            retryable=False,
            idempotency_key="admission-succeeded-1",
            recorded_at=4_003,
        ),
        sequence=3,
    )
    first = LineageEvent.create(selected, sequence=1, prev_event_digest=None)
    second = LineageEvent.create(started, sequence=2, prev_event_digest=first.event_digest)
    third = LineageEvent.create(succeeded, sequence=3, prev_event_digest=second.event_digest)
    return CausalGraph.from_events((first, second, third))


class GraphAdmissionTests(unittest.TestCase):
    def test_verified_graph_has_stable_canonical_graph_digest(self):
        graph = verified_graph()
        self.assertTrue(graph.graph_digest.startswith("sha256:"))
        self.assertEqual(graph.graph_digest, CausalGraph.from_events(graph.events).graph_digest)

    def test_graph_digest_rejects_forged_lineage_event(self):
        graph = verified_graph()
        forged_event = replace(graph.events[1], event_digest="sha256:" + "f" * 64)
        forged = CausalGraph(events=(graph.events[0], forged_event, graph.events[2]), edges=graph.edges)
        with self.assertRaises(ValueError):
            _ = forged.graph_digest

    def test_graph_digest_rejects_forged_causal_edge(self):
        graph = verified_graph()
        forged_edge = replace(graph.edges[0], edge_digest="sha256:" + "f" * 64)
        forged = CausalGraph(events=graph.events, edges=(forged_edge, *graph.edges[1:]))
        with self.assertRaises(ValueError):
            _ = forged.graph_digest

    def test_graph_digest_rejects_edge_with_unknown_endpoint(self):
        graph = verified_graph()
        unknown = "sha256:" + "9" * 64
        edge = CausalEdge.create("receipt", graph.events[0].event_digest, unknown)
        invalid = CausalGraph(events=graph.events, edges=(*graph.edges, edge))
        with self.assertRaises(ValueError):
            _ = invalid.graph_digest

    def test_causal_edge_relation_requires_matching_handoff_id(self):
        graph = verified_graph()
        parent = graph.events[0].event_digest
        child = graph.events[1].event_digest
        with self.assertRaises(ValueError):
            CausalEdge.create("receipt", parent, child, handoff_id="unexpected")
        with self.assertRaises(ValueError):
            CausalEdge.create("handoff", parent, child)

    def test_graph_digest_rejects_malformed_handoff_object_fail_closed(self):
        graph = verified_graph()
        invalid = CausalGraph(
            events=graph.events,
            edges=graph.edges,
            handoffs=({"handoff_id": "not-a-typed-link"},),
        )
        with self.assertRaises(ValueError):
            _ = invalid.graph_digest


if __name__ == "__main__":
    unittest.main()
