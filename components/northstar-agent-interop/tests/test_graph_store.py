import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
TEST_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(COMPONENT_ROOT))
sys.path.insert(0, str(COMPONENT_ROOT.parent / "northstar-host"))
sys.path.insert(0, str(COMPONENT_ROOT.parent / "northstar-run-contract"))
sys.path.insert(0, str(TEST_ROOT))

from dataclasses import replace  # noqa: E402

from route_causality import CausalEdge, CausalGraph, HandoffLink  # noqa: E402
from graph_store import (  # noqa: E402
    GraphEvidenceCursor,
    GraphEvidenceRecord,
    GraphEvidenceStore,
)
from route_lineage import LineageEvent  # noqa: E402
from test_graph_admission import verified_graph  # noqa: E402
from test_route_state_causality import valid_child_events, valid_retry_events  # noqa: E402


def _record_digest(value):
    unsigned = {key: value[key] for key in (
        "schema_version", "sequence", "prev_record_digest", "graph_digest",
        "segment_lengths", "event_digests", "edges", "handoffs",
    )}
    return "sha256:" + hashlib.sha256(
        json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _graph_digest(value):
    unsigned = {
        "schema_version": "northstar.causal-graph.v1",
        "segment_lengths": value["segment_lengths"],
        "event_digests": value["event_digests"],
        "edges": value["edges"],
        "handoffs": value["handoffs"],
    }
    return "sha256:" + hashlib.sha256(
        json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _lineage_events(route_events):
    result = []
    previous = None
    for sequence, route_event in enumerate(route_events, start=1):
        event = LineageEvent.create(
            route_event,
            sequence=sequence,
            prev_event_digest=previous,
        )
        result.append(event)
        previous = event.event_digest
    return tuple(result)


def _multi_segment_graph():
    parent = _lineage_events(valid_retry_events())
    child = _lineage_events(valid_child_events())
    return CausalGraph.from_segments(
        (parent, child),
        handoffs=(HandoffLink(
            "handoff-store-1",
            parent[-1].event_digest,
            child[0].event_digest,
            "codex",
            "hermes",
        ),),
    )


class GraphEvidenceStoreTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tempdir.name) / "graph-evidence.jsonl"
        self.graph = verified_graph()

    def tearDown(self):
        self.tempdir.cleanup()

    def test_admit_and_restart_recovery_preserve_verified_graph_commitment(self):
        store = GraphEvidenceStore(self.path)
        record = store.admit(self.graph)
        recovery = GraphEvidenceStore(self.path).recover()
        self.assertIsInstance(record, GraphEvidenceRecord)
        self.assertEqual(record.graph_digest, self.graph.graph_digest)
        self.assertEqual(record.segment_lengths, self.graph.segment_lengths)
        self.assertEqual(record.handoffs, self.graph.handoffs)
        self.assertEqual(recovery.verdict, "verified")
        self.assertEqual(recovery.records, (record,))
        self.assertEqual(
            recovery.cursor,
            GraphEvidenceCursor(1, record.record_digest),
        )

    def test_admitting_same_graph_is_idempotent(self):
        store = GraphEvidenceStore(self.path)
        first = store.admit(self.graph)
        second = store.admit(CausalGraph.from_events(self.graph.events))
        self.assertEqual(second, first)
        self.assertEqual(len(store.recover().records), 1)

    def test_admission_rejects_forged_graph_without_creating_store(self):
        forged_edge = replace(self.graph.edges[0], edge_digest="sha256:" + "f" * 64)
        forged = CausalGraph(
            events=self.graph.events,
            edges=(forged_edge, *self.graph.edges[1:]),
        )
        with self.assertRaises(ValueError):
            GraphEvidenceStore(self.path).admit(forged)
        self.assertFalse(self.path.exists())

    def test_admission_rejects_unknown_graph_endpoint_without_mutation(self):
        unknown = "sha256:" + "9" * 64
        invalid_edge = CausalEdge.create(
            "receipt",
            self.graph.events[0].event_digest,
            unknown,
        )
        invalid = CausalGraph(
            events=self.graph.events,
            edges=(*self.graph.edges, invalid_edge),
        )
        with self.assertRaises(ValueError):
            GraphEvidenceStore(self.path).admit(invalid)
        self.assertFalse(self.path.exists())

    def test_recovery_rejects_record_with_rewritten_graph_digest(self):
        store = GraphEvidenceStore(self.path)
        record = store.admit(self.graph)
        row = record.to_dict()
        row["graph_digest"] = "sha256:" + "f" * 64
        row["record_digest"] = _record_digest(row)
        self.path.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            store.recover()

    def test_recovery_rejects_record_with_invalid_segment_coverage(self):
        store = GraphEvidenceStore(self.path)
        record = store.admit(self.graph)
        row = record.to_dict()
        row["segment_lengths"] = [1]
        row["graph_digest"] = _graph_digest(row)
        row["record_digest"] = _record_digest(row)
        self.path.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            store.recover()

    def test_recovery_rejects_duplicate_graph_records(self):
        store = GraphEvidenceStore(self.path)
        record = store.admit(self.graph)
        duplicate = dict(record.to_dict())
        duplicate["sequence"] = 2
        duplicate["prev_record_digest"] = record.record_digest
        duplicate["record_digest"] = _record_digest(duplicate)
        with self.path.open("ab") as stream:
            stream.write(json.dumps(duplicate, sort_keys=True).encode() + b"\n")
        with self.assertRaises(ValueError):
            store.recover()

    def test_two_distinct_graphs_form_a_record_chain_and_cursor_detects_rollback(self):
        second_graph = CausalGraph.from_events(self.graph.events[:2])
        store = GraphEvidenceStore(self.path)
        first = store.admit(self.graph)
        second = store.admit(second_graph)
        self.assertNotEqual(first.graph_digest, second.graph_digest)
        recovery = GraphEvidenceStore(self.path).recover()
        self.assertEqual(recovery.records, (first, second))
        self.assertEqual(recovery.cursor, GraphEvidenceCursor(2, second.record_digest))
        self.path.write_text(self.path.read_text(encoding="utf-8").splitlines()[0] + "\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            GraphEvidenceStore(self.path).recover(expected_cursor=recovery.cursor)

    def test_admission_failure_does_not_replace_existing_store(self):
        store = GraphEvidenceStore(self.path)
        first = store.admit(self.graph)
        original = self.path.read_bytes()
        with mock.patch.object(store, "_publish", side_effect=OSError("simulated publish failure")):
            with self.assertRaises(OSError):
                store.admit(CausalGraph.from_events(self.graph.events[:2]))
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(store.recover().records, (first,))

    def test_cross_segment_graph_round_trips_handoff_structure(self):
        graph = _multi_segment_graph()
        store = GraphEvidenceStore(self.path)
        record = store.admit(graph)
        recovered = GraphEvidenceStore(self.path).recover().records[0]
        self.assertEqual(record.graph_digest, graph.graph_digest)
        self.assertEqual(recovered.segment_lengths, graph.segment_lengths)
        self.assertEqual(recovered.handoffs, graph.handoffs)
        self.assertIn("handoff", [edge.relation for edge in recovered.edges])

    def test_recovery_rejects_handoff_declaration_without_matching_edge(self):
        graph = _multi_segment_graph()
        store = GraphEvidenceStore(self.path)
        record = store.admit(graph)
        row = record.to_dict()
        row["edges"] = [edge for edge in row["edges"] if edge["relation"] != "handoff"]
        row["graph_digest"] = _graph_digest(row)
        row["record_digest"] = _record_digest(row)
        self.path.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            store.recover()


if __name__ == "__main__":
    unittest.main()
