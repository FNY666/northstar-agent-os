"""A persisted graph projection must be checkable against the source it came from."""
import sys
import unittest
from dataclasses import replace
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
TEST_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(COMPONENT_ROOT))
sys.path.insert(0, str(COMPONENT_ROOT.parent / "northstar-host"))
sys.path.insert(0, str(COMPONENT_ROOT.parent / "northstar-run-contract"))
sys.path.insert(0, str(TEST_ROOT))

from graph_store import (  # noqa: E402
    GraphEvidenceRecord,
    GraphEvidenceStore,
    verify_projection_against_source,
)
from route_lineage import LineageEvent  # noqa: E402
from test_graph_admission import verified_graph  # noqa: E402


def admitted_record(graph=None):
    source = verified_graph() if graph is None else graph
    return GraphEvidenceRecord.create(source, sequence=1, prev_record_digest=None)


def extended(events):
    """Return the same chain with one more event appended by the source."""
    last = events[-1]
    extra = LineageEvent.create(
        last.route_event,
        sequence=len(events) + 1,
        prev_event_digest=last.event_digest,
    )
    return (*events, extra)


class GraphProjectionVerificationTests(unittest.TestCase):
    """The record already stores the source event digests; nothing read them."""

    def test_projection_matching_its_source_is_current(self):
        record = admitted_record()
        verdict = verify_projection_against_source(record, verified_graph().events)
        self.assertEqual(verdict.verdict, "projection-current")
        self.assertEqual(verdict.record_sequence, 1)

    def test_source_that_grew_past_the_projection_is_extended_not_current(self):
        record = admitted_record()
        verdict = verify_projection_against_source(record, extended(verified_graph().events))
        self.assertEqual(verdict.verdict, "projection-extended")
        self.assertEqual(verdict.record_sequence, 1)

    def test_truncated_source_is_stale(self):
        record = admitted_record()
        verdict = verify_projection_against_source(record, verified_graph().events[:-1])
        self.assertEqual(verdict.verdict, "projection-stale")

    def test_replaced_source_is_stale(self):
        record = admitted_record()
        events = verified_graph().events
        forged = replace(events[0], event_digest="sha256:" + "a" * 64)
        verdict = verify_projection_against_source(record, (forged, *events[1:]))
        self.assertEqual(verdict.verdict, "projection-stale")

    def test_source_without_events_is_unknown_rather_than_stale(self):
        record = admitted_record()
        verdict = verify_projection_against_source(record, ())
        self.assertEqual(verdict.verdict, "projection-unknown")
        self.assertIsNone(verdict.record_sequence)

    def test_mismatched_record_pin_is_unknown(self):
        record = admitted_record()
        verdict = verify_projection_against_source(
            record,
            verified_graph().events,
            expected_record_digest="sha256:" + "b" * 64,
        )
        self.assertEqual(verdict.verdict, "projection-unknown")
        self.assertIn("pin", verdict.reason)

    def test_matching_record_pin_keeps_the_current_verdict(self):
        record = admitted_record()
        verdict = verify_projection_against_source(
            record,
            verified_graph().events,
            expected_record_digest=record.record_digest,
        )
        self.assertEqual(verdict.verdict, "projection-current")

    def test_record_with_a_forged_graph_commitment_is_stale(self):
        # The record stays internally consistent, so only re-deriving the
        # commitment from the source can catch it.
        graph = verified_graph()
        record = GraphEvidenceRecord.create(graph, sequence=1, prev_record_digest=None)
        forged = replace(record, graph_digest="sha256:" + "c" * 64)
        verdict = verify_projection_against_source(forged, graph.events)
        self.assertEqual(verdict.verdict, "projection-stale")
        self.assertIn("commitment", verdict.reason)

    def test_no_verdict_ever_authorizes_execution(self):
        record = admitted_record()
        events = verified_graph().events
        cases = (
            (events, None),
            (extended(events), None),
            (events[:-1], None),
            ((), None),
            (events, "sha256:" + "b" * 64),
        )
        for source, pin in cases:
            with self.subTest(pin=pin):
                verdict = verify_projection_against_source(
                    record, source, expected_record_digest=pin
                )
                self.assertFalse(verdict.execution_authorized)

    def test_projection_can_be_checked_after_a_store_restart(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            store = GraphEvidenceStore(Path(directory) / "graph.jsonl")
            record = store.admit(verified_graph())
            recovered = GraphEvidenceStore(Path(directory) / "graph.jsonl").recover()
        self.assertEqual(recovered.verdict, "verified")
        verdict = verify_projection_against_source(
            recovered.records[-1], verified_graph().events
        )
        self.assertEqual(verdict.verdict, "projection-current")
        self.assertEqual(verdict.record_sequence, record.sequence)

    def test_invalid_inputs_are_rejected(self):
        record = admitted_record()
        with self.assertRaises(ValueError):
            verify_projection_against_source("sha256:" + "1" * 64, verified_graph().events)
        with self.assertRaises(ValueError):
            verify_projection_against_source(record, 7)
        with self.assertRaises(ValueError):
            verify_projection_against_source(record, ("sha256:" + "1" * 64,))
        with self.assertRaises(ValueError):
            verify_projection_against_source(record, verified_graph().events, expected_record_digest="not-a-digest")


if __name__ == "__main__":
    unittest.main()
