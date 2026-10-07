"""Tests for virtual_nodes.py (Dynamo-style vnode ownership ledger)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from virtual_nodes import (  # noqa: E402
    ACTION_ASSIGNED,
    SCHEMA_PIN,
    VIRTUAL_NODES_VERSION,
    MoveRecord,
    NoNodesError,
    UnassignedVNodeError,
    UnknownNodeError,
    UnknownVNodeError,
    VirtualNodes,
    VirtualNodesError,
    virtual_nodes_audit_event,
)


def make_ledger(num_vnodes=16):
    return VirtualNodes(num_vnodes=num_vnodes)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(VIRTUAL_NODES_VERSION, "virtual-nodes.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.virtual-nodes.v1")


class TestConstruction(unittest.TestCase):
    def test_bad_num_vnodes(self):
        for bad in (0, -4):
            with self.assertRaises(ValueError):
                VirtualNodes(num_vnodes=bad)
        for bad in (True, "16", 2.5, None):
            with self.assertRaises(TypeError):
                VirtualNodes(num_vnodes=bad)


class TestAssign(unittest.TestCase):
    def test_assign_roundtrip(self):
        vn = make_ledger()
        rec = vn.assign("db-1", 4)
        self.assertEqual(rec.assigned, (0, 1, 2, 3))
        self.assertEqual(rec.node_id, "db-1")
        self.assertEqual(rec.requested, 4)
        self.assertEqual(rec.schema, SCHEMA_PIN)
        self.assertEqual(vn.vnodes_for("db-1"), (0, 1, 2, 3))

    def test_assign_lowest_slots_first(self):
        vn = make_ledger()
        vn.assign("a", 3)
        rec = vn.assign("b", 2)
        self.assertEqual(rec.assigned, (3, 4))

    def test_assign_all_when_count_none(self):
        vn = make_ledger(num_vnodes=6)
        rec = vn.assign("solo")
        self.assertEqual(len(rec.assigned), 6)
        self.assertIsNone(rec.requested)
        self.assertEqual(vn.unassigned(), ())

    def test_assign_capped_by_free(self):
        vn = make_ledger(num_vnodes=4)
        rec = vn.assign("x", 100)
        self.assertEqual(len(rec.assigned), 4)

    def test_assign_zero_is_noop(self):
        vn = make_ledger()
        rec = vn.assign("x", 0)
        self.assertEqual(rec.assigned, ())
        self.assertEqual(vn.unassigned(), tuple(range(16)))

    def test_assign_bad_inputs(self):
        vn = make_ledger()
        with self.assertRaises(TypeError):
            vn.assign(123, 2)
        with self.assertRaises(ValueError):
            vn.assign("", 2)
        with self.assertRaises(ValueError):
            vn.assign("x", -1)
        with self.assertRaises(TypeError):
            vn.assign("x", True)
        with self.assertRaises(TypeError):
            vn.assign("x", 2.5)


class TestOwner(unittest.TestCase):
    def setUp(self):
        self.vn = make_ledger(num_vnodes=8)
        self.vn.assign("n1", 5)
        self.vn.assign("n2", 3)

    def test_owner(self):
        self.assertEqual(self.vn.owner(0), "n1")
        self.assertEqual(self.vn.owner(7), "n2")

    def test_owner_unassigned_raises(self):
        vn = make_ledger(num_vnodes=8)
        with self.assertRaises(UnassignedVNodeError):
            vn.owner(3)

    def test_owner_out_of_range_raises(self):
        for bad in (-1, 8, 10**6):
            with self.assertRaises(UnknownVNodeError):
                self.vn.owner(bad)
        with self.assertRaises(TypeError):
            self.vn.owner("3")
        with self.assertRaises(TypeError):
            self.vn.owner(True)

    def test_owner_of_key(self):
        key = "orders/42"
        slot = int.from_bytes(
            __import__("hashlib").sha256(
                b"northstar.virtual-nodes.v1\x00" + key.encode()
            ).digest(),
            "big",
        ) % 8
        self.assertEqual(self.vn.owner_of_key(key), self.vn.owner(slot))

    def test_owner_of_key_bad_inputs(self):
        with self.assertRaises(TypeError):
            self.vn.owner_of_key(42)
        with self.assertRaises(ValueError):
            self.vn.owner_of_key("")


class TestRebalance(unittest.TestCase):
    def test_rebalance_evens_out(self):
        vn = make_ledger(num_vnodes=12)
        vn.assign("a", 10)
        vn.assign("b", 2)
        plan = vn.rebalance()
        self.assertEqual(plan.schema, SCHEMA_PIN)
        counts = {n: len(vn.vnodes_for(n)) for n in vn.nodes()}
        self.assertEqual(counts, {"a": 6, "b": 6})
        self.assertTrue(all(isinstance(m, MoveRecord) for m in plan.moves))
        # No moves leave two hosts disagreeing: digest is stable.
        other = make_ledger(num_vnodes=12)
        other.assign("a", 10)
        other.assign("b", 2)
        other.rebalance()
        self.assertEqual(plan.owners_digest, other._ledger_digest())

    def test_rebalance_noop_when_even(self):
        vn = make_ledger(num_vnodes=8)
        vn.assign("a", 4)
        vn.assign("b", 4)
        plan = vn.rebalance()
        self.assertEqual(plan.moves, ())

    def test_rebalance_remainder_to_earliest(self):
        vn = make_ledger(num_vnodes=10)
        vn.assign("a", 8)
        vn.assign("b", 2)
        vn.rebalance()
        self.assertEqual(len(vn.vnodes_for("a")), 5)
        self.assertEqual(len(vn.vnodes_for("b")), 5)

    def test_rebalance_no_nodes_raises(self):
        with self.assertRaises(NoNodesError):
            make_ledger().rebalance()


class TestDrain(unittest.TestCase):
    def test_drain(self):
        vn = make_ledger(num_vnodes=9)
        vn.assign("a", 3)
        vn.assign("b", 3)
        vn.assign("c", 3)
        plan = vn.drain("c")
        self.assertEqual(len(plan.moves), 3)
        self.assertTrue(all(m.src == "c" for m in plan.moves))
        self.assertEqual(vn.vnodes_for("c"), ())
        self.assertNotIn("c", vn.nodes())
        self.assertEqual(vn.unassigned(), ())
        self.assertEqual(
            sorted(len(vn.vnodes_for(n)) for n in vn.nodes()), [4, 5]
        )

    def test_drain_unknown_node(self):
        vn = make_ledger()
        vn.assign("a", 4)
        with self.assertRaises(UnknownNodeError):
            vn.drain("ghost")

    def test_drain_last_node_refused(self):
        vn = make_ledger(num_vnodes=4)
        vn.assign("only", 4)
        with self.assertRaises(VirtualNodesError):
            vn.drain("only")


class TestViews(unittest.TestCase):
    def test_nodes_first_assigned_order(self):
        vn = make_ledger()
        vn.assign("z", 2)
        vn.assign("m", 2)
        vn.assign("a", 2)
        self.assertEqual(vn.nodes(), ("z", "m", "a"))
        self.assertEqual(len(vn), 3)

    def test_unassigned(self):
        vn = make_ledger(num_vnodes=5)
        vn.assign("n", 2)
        self.assertEqual(vn.unassigned(), (2, 3, 4))

    def test_stats(self):
        vn = make_ledger(num_vnodes=8)
        vn.assign("n1", 5)
        stats = vn.stats()
        self.assertEqual(stats["schema"], SCHEMA_PIN)
        self.assertEqual(stats["num_vnodes"], 8)
        self.assertEqual(stats["assigned"], 5)
        self.assertEqual(stats["unassigned"], 3)
        self.assertTrue(stats["ledger_digest"].startswith("sha256:"))


class TestAudit(unittest.TestCase):
    def test_audit_event(self):
        vn = make_ledger(num_vnodes=8)
        vn.assign("n1", 5)
        ev = virtual_nodes_audit_event(ACTION_ASSIGNED, vn, "n1", 7)
        self.assertEqual(ev["event"], "virtual-nodes.assigned")
        self.assertEqual(ev["node_id"], "n1")
        self.assertEqual(ev["assigned"], 5)
        self.assertEqual(ev["audit_seq"], 7)

    def test_audit_bad_action(self):
        vn = make_ledger()
        with self.assertRaises(ValueError):
            virtual_nodes_audit_event("explode", vn, None, 0)

    def test_audit_bad_seq(self):
        vn = make_ledger()
        with self.assertRaises(ValueError):
            virtual_nodes_audit_event(ACTION_ASSIGNED, vn, None, -1)
        with self.assertRaises(ValueError):
            virtual_nodes_audit_event(ACTION_ASSIGNED, vn, None, True)


class TestMain(unittest.TestCase):
    def test_main(self):
        import io
        import subprocess

        proc = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parents[1] / "virtual_nodes.py")],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("virtual-nodes OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
