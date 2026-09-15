"""The lineage log is appended by more than one writer in the same directory."""
import shutil
import tempfile
import threading
import unittest
from pathlib import Path

from route_lineage import ZERO_DIGEST, LineageError, LineageGraph
from test_route_lineage_rollback import v2_event


class LineageConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.log = self.root / "lineage.jsonl"

    def _graph(self):
        return LineageGraph.from_path(self.log) if self.log.exists() else LineageGraph(self.log)

    def _append(self, event_id):
        graph = self._graph()
        graph.append(
            v2_event(
                "planned",
                len(graph.events) + 1,
                graph._head_digest() or ZERO_DIGEST,
                event_id,
            )
        )

    def test_a_stale_writer_is_refused_instead_of_writing_a_duplicate_sequence(self):
        first = LineageGraph(self.log)
        first.append(v2_event("planned", 1, ZERO_DIGEST, "evt-1"))
        stale = LineageGraph(self.log)
        with self.assertRaises(LineageError):
            stale.append(v2_event("planned", 1, ZERO_DIGEST, "evt-stale"))
        self.assertEqual(len(self.log.read_text(encoding="utf-8").splitlines()), 1)

    def test_concurrent_writers_leave_a_loadable_log(self):
        results = []
        lock = threading.Lock()

        def worker(prefix):
            for index in range(4):
                for _attempt in range(8):
                    try:
                        self._append("%s-%d" % (prefix, index))
                    except LineageError:
                        continue
                    else:
                        with lock:
                            results.append(1)
                    break

        threads = [threading.Thread(target=worker, args=("w%d" % number,)) for number in range(3)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        graph = LineageGraph.from_path(self.log)
        sequences = [event.sequence for event in graph.events.values()]
        self.assertEqual(sequences, list(range(1, len(sequences) + 1)))
        self.assertEqual(len(sequences), sum(results))
        self.assertEqual(graph.mark_state, "verified")
