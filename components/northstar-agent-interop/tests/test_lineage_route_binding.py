"""Lineage verification must be bound to the route it claims to verify."""
import unittest

from route_lineage import LineageGraph, RouteLineageEvent, verify_lineage

IDENT = {
    "target_agent_id": "codex",
    "provider": "openai",
    "deadline_at": 90,
    "decision_fingerprint": "sha256:" + "b" * 64,
    "payload_digest": "sha256:" + "a" * 64,
    "capabilities": ["workspace:read"],
}
ROUTE_RECORD = {
    "selected_agent_id": "codex",
    "selected_provider": "openai",
    "deadline_at": 90,
    "decision_fingerprint": "sha256:" + "b" * 64,
    "payload_digest": "sha256:" + "a" * 64,
}


def event(event_id, status="planned", parent=None, route_id="r1"):
    return RouteLineageEvent.from_dict({
        "schema_version": "northstar.route-lineage.v1",
        "event_id": event_id,
        "route_id": route_id,
        "parent_event_id": parent,
        "receipt_id": "receipt-" + event_id,
        "status": status,
        "target_agent_id": "codex",
        "provider": "openai",
        "capabilities": ["workspace:read"],
        "deadline_at": 90,
        "payload_digest": "sha256:" + "a" * 64,
        "decision_fingerprint": "sha256:" + "b" * 64,
        "retryable": False,
    })


def two_route_graph():
    graph = LineageGraph()
    graph.append(event("a1", route_id="r-a"))
    graph.append(event("a2", "dispatched", "a1", route_id="r-a"))
    graph.append(event("b1", route_id="r-b"))
    graph.append(event("b2", "dispatched", "b1", route_id="r-b"))
    graph.append(event("b3", "succeeded", "b2", route_id="r-b"))
    return graph


class LineageRouteBindingTests(unittest.TestCase):
    def test_an_unpinned_route_is_not_verified_from_another_route(self):
        verdict = verify_lineage(
            two_route_graph(), route_record=ROUTE_RECORD, handoff=IDENT
        )
        self.assertEqual(verdict.verdict, "unknown")
        self.assertIn("route identity not pinned for a multi-route lineage", verdict.reasons)

    def test_the_requested_route_is_the_one_verified(self):
        verdict = verify_lineage(
            two_route_graph(), route_record=ROUTE_RECORD, handoff=IDENT, route_id="r-b"
        )
        self.assertEqual(verdict.verdict, "verified")

    def test_another_route_s_success_does_not_verify_an_unfinished_route(self):
        verdict = verify_lineage(
            two_route_graph(), route_record=ROUTE_RECORD, handoff=IDENT, route_id="r-a"
        )
        self.assertNotEqual(verdict.verdict, "verified")

    def test_a_single_route_lineage_still_verifies_without_the_extra_argument(self):
        graph = LineageGraph()
        graph.append(event("e1"))
        graph.append(event("e2", "dispatched", "e1"))
        graph.append(event("e3", "succeeded", "e2"))
        verdict = verify_lineage(graph, route_record=ROUTE_RECORD, handoff=IDENT)
        self.assertEqual(verdict.verdict, "verified")


if __name__ == "__main__":
    unittest.main()


def sibling_branch_graph():
    graph = LineageGraph()
    graph.append(event("e1"))
    graph.append(event("e2", "dispatched", "e1"))
    graph.append(event("e3", "dispatched", "e1"))
    graph.append(event("e4", "succeeded", "e2"))
    return graph


class UnresolvedBranchVerificationTests(unittest.TestCase):
    def test_a_route_with_an_unaccounted_branch_is_not_verified(self):
        verdict = verify_lineage(
            sibling_branch_graph(), route_record=ROUTE_RECORD, handoff=IDENT, route_id="r1"
        )
        self.assertNotEqual(verdict.verdict, "verified")
        self.assertIn("unresolved attempt branch", verdict.reasons)

    def test_a_fully_accounted_route_is_still_verified(self):
        graph = LineageGraph()
        graph.append(event("e1"))
        graph.append(event("e2", "dispatched", "e1"))
        graph.append(event("e3", "succeeded", "e2"))
        verdict = verify_lineage(graph, route_record=ROUTE_RECORD, handoff=IDENT, route_id="r1")
        self.assertEqual(verdict.verdict, "verified")
