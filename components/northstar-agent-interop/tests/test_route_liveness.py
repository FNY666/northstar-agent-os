"""A route's lineage decides whether it may accept a new attempt."""
import shutil
import tempfile
import unittest
from pathlib import Path

from route_lineage import (
    INTEGRITY_SCHEMA,
    ZERO_DIGEST,
    LineageGraph,
    RouteLineageEvent,
    derive_retry,
)
from route_liveness import evaluate_route_liveness

D = lambda seed: "sha256:" + seed * 64


def event(status, sequence, prev_digest, event_id, retryable=False):
    return RouteLineageEvent(
        schema_version=INTEGRITY_SCHEMA,
        event_id=event_id,
        route_id="route-1",
        parent_event_id=None,
        receipt_id="rcpt-1",
        status=status,
        target_agent_id="agent-a",
        provider="local",
        capabilities=("fs:read",),
        deadline_at=1000,
        payload_digest=D("a"),
        decision_fingerprint=D("b"),
        retryable=retryable,
        sequence=sequence,
        prev_event_digest=prev_digest,
    )


class RouteLivenessTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.log = self.root / "lineage.jsonl"
        self.mark = Path(str(self.log) + ".mark.json")

    def build(self, *statuses, retryable=False):
        for stale in (self.log, self.mark):
            if stale.exists():
                stale.unlink()
        graph = LineageGraph(self.log)
        prev = ZERO_DIGEST
        for index, status in enumerate(statuses, start=1):
            item = event(status, index, prev, "evt-%d" % index, retryable)
            graph.append(item)
            prev = item.event_digest.removeprefix("sha256:")
        return graph

    def test_a_route_without_lineage_is_dispatchable(self):
        verdict = evaluate_route_liveness(self.build(), "route-1")
        self.assertEqual(verdict.state, "dispatchable")
        self.assertEqual(verdict.attempt_count, 0)
        self.assertIn("no_prior_attempts", verdict.reasons)
        self.assertFalse(verdict.execution_authorized)

    def test_a_route_without_lineage_cannot_corroborate_its_identity(self):
        verdict = evaluate_route_liveness(self.build(), "route-1")
        self.assertEqual(verdict.state, "dispatchable")
        self.assertIn("route_identity_unverified", verdict.unverified)

    def test_lineage_corroborates_the_identity_of_a_known_route(self):
        verdict = evaluate_route_liveness(self.build("dispatched"), "route-1")
        self.assertNotIn("route_identity_unverified", verdict.unverified)

    def test_declared_routes_corroborate_a_new_route(self):
        verdict = evaluate_route_liveness(
            self.build(), "route-1", declared_routes=("route-1",)
        )
        self.assertEqual(verdict.state, "dispatchable")
        self.assertNotIn("route_identity_unverified", verdict.unverified)

    def test_a_route_outside_the_declared_set_is_refused(self):
        with self.assertRaises(ValueError):
            evaluate_route_liveness(self.build(), "route-1", declared_routes=("route-2",))

    def test_an_unfinished_attempt_is_in_flight(self):
        for status in ("planned", "dispatched"):
            verdict = evaluate_route_liveness(self.build(status), "route-1")
            self.assertEqual(verdict.state, "in_flight")

    def test_a_terminal_failure_without_retry_blocks_the_route(self):
        verdict = evaluate_route_liveness(self.build("dispatched", "failed"), "route-1")
        self.assertEqual(verdict.state, "blocked")
        self.assertIn("route_terminal_failed", verdict.reasons)
        self.assertEqual(verdict.active_status, "failed")

    def test_a_retryable_failure_allows_one_more_attempt(self):
        graph = self.build("dispatched", "failed", retryable=True)
        verdict = evaluate_route_liveness(graph, "route-1")
        self.assertEqual(verdict.state, "retryable")
        terminal = graph.events[next(reversed(graph.events))]
        retry = derive_retry(
            terminal, event_id="evt-3", receipt_id="rcpt-1", deadline_at=1000,
            capabilities=["fs:read"],
        )
        self.assertEqual(retry.status, "planned")

    def test_a_successful_route_is_blocked_for_new_attempts(self):
        verdict = evaluate_route_liveness(self.build("dispatched", "succeeded"), "route-1")
        self.assertEqual(verdict.state, "blocked")
        self.assertIn("route_terminal_succeeded", verdict.reasons)

    def test_an_unmarked_log_is_reported_but_still_decided(self):
        self.build("dispatched", "failed")
        self.mark.unlink()
        verdict = evaluate_route_liveness(LineageGraph.from_path(self.log), "route-1")
        self.assertEqual(verdict.state, "blocked")
        self.assertIn("lineage_mark_absent", verdict.unverified)
