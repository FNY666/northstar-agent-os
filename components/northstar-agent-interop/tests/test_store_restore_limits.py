"""Pin the documented limits: a whole-store restore is only caught externally."""
import shutil
import tempfile
import unittest
from pathlib import Path

from evidence_preflight_pins import (
    PreflightPinStore,
    verify_pin_resolution,
)
from evidence_readiness_lease_registry import EvidenceReadinessLeaseRegistry
from readiness_lease_witness import (
    make_registry_witness,
    verify_registry_witness,
)
from route_lineage import ZERO_DIGEST, LineageGraph
from test_evidence_preflight_pins import D, make_preflight
from test_evidence_readiness_lease_registry import lease
from test_route_lineage_rollback import v2_event


class PinStoreRestoreLimitTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.store = PreflightPinStore(self.root / "pins")
        self.backup = self.root / "snapshot"

    def _pin(self, seed):
        return self.store.pin_preflight(
            "plan-a", make_preflight(decision_digest=D(seed)), now=1000
        )

    def test_restoring_an_older_copy_is_stale_only_against_a_remembered_head(self):
        self._pin("a")
        self._pin("b")
        shutil.copytree(self.store._root, self.backup)
        third = self._pin("c")
        shutil.rmtree(self.store._root)
        shutil.copytree(self.backup, self.store._root)
        resolved = self.store.resolve("plan-a")
        self.assertEqual(resolved.state, "pins-current")
        self.assertEqual(resolved.decision_digest, D("b"))
        verdict = verify_pin_resolution(
            resolved,
            self.store,
            expected_chain_head_digest=third.record_digest,
            expected_chain_sequence=3,
        )
        self.assertEqual(verdict.state, "pins-stale")


class LeaseRegistryRestoreLimitTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.registry = EvidenceReadinessLeaseRegistry(self.root / "registry")
        self.backup = self.root / "snapshot"

    def test_a_restored_copy_hides_the_revocation_locally(self):
        item = lease(suffix="a")
        self.registry.register(item)
        shutil.copytree(self.registry.root, self.backup)
        self.registry.revoke(item.lease_digest)
        witness = make_registry_witness(self.registry, item.lease_digest, now=1010)
        shutil.rmtree(self.registry.root)
        shutil.copytree(self.backup, self.registry.root)
        self.assertEqual(
            self.registry.inspect(item.lease_digest, now=1020).state, "active"
        )
        verdict = verify_registry_witness(witness, self.registry, now=1020)
        self.assertEqual(verdict.state, "stale")


class LineageRestoreLimitTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.log = self.root / "lineage.jsonl"
        self.backup = self.root / "snapshot"

    def _append(self, graph, status, sequence):
        event = v2_event(
            status, sequence, graph._head_digest() or ZERO_DIGEST, "evt-%d" % sequence
        )
        graph.append(event)
        return event

    def test_restored_copy_loads_verified_and_only_a_remembered_cursor_notices(self):
        graph = LineageGraph(self.log)
        self._append(graph, "planned", 1)
        self._append(graph, "dispatched", 2)
        shutil.copytree(self.root, self.backup, ignore=shutil.ignore_patterns("snapshot"))
        self._append(graph, "failed", 3)
        for item in self.backup.iterdir():
            shutil.copy2(item, self.root / item.name)
        reloaded = LineageGraph.from_path(self.log)
        self.assertEqual(reloaded.mark_state, "verified")
        self.assertEqual(len(reloaded.events), 2)
        self.assertEqual(len(graph.events), 3)
