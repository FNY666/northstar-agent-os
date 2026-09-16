"""A stored causal edge must stay reconcilable with the source it came from."""
import sys
import unittest
from dataclasses import replace
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMPONENT_ROOT))
sys.path.insert(0, str(COMPONENT_ROOT.parent / "northstar-host"))
sys.path.insert(0, str(COMPONENT_ROOT.parent / "northstar-run-contract"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from causal_store import verify_edge_against_source  # noqa: E402
from test_graph_admission import verified_graph  # noqa: E402


class CausalEdgeReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.graph = verified_graph()
        self.events = self.graph.events
        self.edge = self.graph.edges[0]

    def test_edge_whose_endpoints_are_still_present_is_current(self):
        verdict = verify_edge_against_source(self.edge, self.events)
        self.assertEqual(verdict.verdict, "edge-current")

    def test_edge_whose_event_left_the_source_is_stale(self):
        # Truncating the source back to its first event removes the child end
        # of every later edge, so the index keeps a dangling edge.
        verdict = verify_edge_against_source(self.edge, self.events[:1])
        self.assertEqual(verdict.verdict, "edge-stale")
        self.assertIn("no longer contains", verdict.reason)

    def test_edge_whose_endpoints_are_out_of_order_is_stale(self):
        verdict = verify_edge_against_source(self.edge, tuple(reversed(self.events)))
        self.assertEqual(verdict.verdict, "edge-stale")
        self.assertIn("order", verdict.reason)

    def test_edge_pointing_at_an_unknown_event_is_stale(self):
        forged = replace(self.edge, child_event_digest="sha256:" + "e" * 64)
        verdict = verify_edge_against_source(forged, self.events)
        self.assertEqual(verdict.verdict, "edge-stale")

    def test_source_without_events_is_unknown_rather_than_stale(self):
        verdict = verify_edge_against_source(self.edge, ())
        self.assertEqual(verdict.verdict, "edge-unknown")

    def test_no_verdict_ever_authorizes_execution(self):
        for source in (self.events, self.events[:1], (), tuple(reversed(self.events))):
            with self.subTest(source_length=len(source)):
                self.assertFalse(verify_edge_against_source(self.edge, source).execution_authorized)

    def test_invalid_inputs_are_rejected(self):
        with self.assertRaises(ValueError):
            verify_edge_against_source("not-an-edge", self.events)
        with self.assertRaises(ValueError):
            verify_edge_against_source(self.edge, 7)
        with self.assertRaises(ValueError):
            verify_edge_against_source(self.edge, ("not-an-event",))


if __name__ == "__main__":
    unittest.main()
