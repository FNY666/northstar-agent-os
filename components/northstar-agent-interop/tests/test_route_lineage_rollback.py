"""Rollback detection for the lineage log (high-water mark)."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from route_lineage import (
    INTEGRITY_SCHEMA,
    ZERO_DIGEST,
    LineageError,
    LineageGraph,
    RouteLineageEvent,
    select_active_terminal,
)

D = lambda seed: "sha256:" + seed * 64


def v2_event(status, sequence, prev_digest, event_id):
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
        retryable=False,
        sequence=sequence,
        prev_event_digest=prev_digest,
    )


class LineageRollbackTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.log = self.root / "lineage.jsonl"
        self.mark = Path(str(self.log) + ".mark.json")

    def build(self, statuses):
        graph = LineageGraph(self.log)
        prev = ZERO_DIGEST
        for index, status in enumerate(statuses, start=1):
            event = v2_event(status, index, prev, "evt-%d" % index)
            graph.append(event)
            prev = event.event_digest.removeprefix("sha256:")
        return graph

    def lines(self):
        return self.log.read_text(encoding="utf-8").splitlines(True)

    def test_truncated_terminal_event_is_rejected(self):
        self.build(["planned", "dispatched", "failed"])
        self.log.write_text("".join(self.lines()[:2]), encoding="utf-8")
        with self.assertRaises(LineageError):
            LineageGraph.from_path(self.log)

    def test_truncated_route_does_not_read_as_active(self):
        graph = self.build(["planned", "dispatched", "failed"])
        self.assertEqual(select_active_terminal(graph, "route-1").status, "failed")
        self.log.write_text("".join(self.lines()[:2]), encoding="utf-8")
        try:
            reloaded = LineageGraph.from_path(self.log)
        except LineageError:
            return
        self.assertNotEqual(select_active_terminal(reloaded, "route-1").status, "dispatched")

    def test_mark_absent_log_stays_readable_but_unverified(self):
        graph = self.build(["planned", "failed"])
        self.mark.unlink()
        reloaded = LineageGraph.from_path(self.log)
        self.assertEqual(reloaded.mark_state, "mark_absent")
        self.assertEqual(select_active_terminal(reloaded, "route-1").status, "failed")

    def test_log_ahead_of_mark_is_repaired(self):
        graph = self.build(["planned", "dispatched"])
        event = v2_event("failed", 3, graph._head_digest(), "evt-3")
        with self.log.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":")) + "\n")
        reloaded = LineageGraph.from_path(self.log)
        self.assertEqual(reloaded.mark_state, "repaired")
        mark = json.loads(self.mark.read_text(encoding="utf-8"))
        self.assertEqual(mark["high_water"]["sequence"], 3)

    def test_append_keeps_mark_in_sync(self):
        graph = self.build(["planned"])
        graph.append(v2_event("failed", 2, graph._head_digest(), "evt-2"))
        reloaded = LineageGraph.from_path(self.log)
        self.assertEqual(reloaded.mark_state, "verified")
