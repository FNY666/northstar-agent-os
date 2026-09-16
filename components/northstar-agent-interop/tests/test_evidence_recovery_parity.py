"""Every evidence store must agree that reading nothing verifies nothing."""
import sys
import tempfile
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMPONENT_ROOT))
sys.path.insert(0, str(COMPONENT_ROOT.parent / "northstar-host"))
sys.path.insert(0, str(COMPONENT_ROOT.parent / "northstar-run-contract"))

from causal_store import CausalEvidenceStore  # noqa: E402
from graph_store import GraphEvidenceStore  # noqa: E402
from interop_contract import RECOVERY_EMPTY  # noqa: E402
from route_lineage import RouteLineage  # noqa: E402

_JOURNALS = ("lineage.jsonl", "graph.jsonl", "causal.jsonl")


class EvidenceRecoveryParityTests(unittest.TestCase):
    """The three persistence layers must not drift apart on the empty case.

    Each layer has its own record envelope and its own tamper checks, and the
    empty journal was fixed one layer at a time. Nothing but this test stops a
    future edit from repairing one layer and leaving the others fail-open.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)

    def tearDown(self):
        self.tempdir.cleanup()

    def layers(self):
        return (
            ("route lineage", RouteLineage(self.root / "lineage.jsonl"), "events"),
            ("graph evidence", GraphEvidenceStore(self.root / "graph.jsonl"), "records"),
            ("causal evidence", CausalEvidenceStore(self.root / "causal.jsonl"), "records"),
        )

    def test_absent_journals_are_empty_and_read_nothing_in_every_layer(self):
        for name, store, field in self.layers():
            with self.subTest(layer=name):
                recovery = store.recover()
                self.assertEqual(recovery.verdict, RECOVERY_EMPTY)
                self.assertEqual(tuple(getattr(recovery, field)), ())
                self.assertIsNone(recovery.cursor)

    def test_zero_byte_journals_are_empty_in_every_layer(self):
        for journal in _JOURNALS:
            (self.root / journal).write_bytes(b"")
        for name, store, _ in self.layers():
            with self.subTest(layer=name):
                self.assertEqual(store.recover().verdict, RECOVERY_EMPTY)


if __name__ == "__main__":
    unittest.main()
