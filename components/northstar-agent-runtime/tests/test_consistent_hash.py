"""Tests for consistent_hash.py (consistent-hash ring with virtual nodes)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from consistent_hash import (  # noqa: E402
    CONSISTENT_HASH_VERSION,
    SCHEMA_PIN,
    ConsistentHash,
    ConsistentHashError,
    EmptyRingError,
    RingSnapshot,
    consistent_hash_audit_event,
)


def make_ring(replicas=16, *nodes):
    ring = ConsistentHash(replicas=replicas)
    for n in nodes:
        ring.add_node(n)
    return ring


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(CONSISTENT_HASH_VERSION, "consistent-hash.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.consistent-hash.v1")


class TestConstruction(unittest.TestCase):
    def test_default_replicas(self):
        ring = ConsistentHash()
        self.assertEqual(ring.replicas, 100)

    def test_custom_replicas(self):
        ring = ConsistentHash(replicas=8)
        ring.add_node("n1")
        self.assertEqual(len(ring.snapshot().node_counts), 1)
        self.assertEqual(ring.snapshot().total_points, 8)

    def test_replicas_zero_rejected(self):
        with self.assertRaises(ValueError):
            ConsistentHash(replicas=0)

    def test_replicas_negative_rejected(self):
        with self.assertRaises(ValueError):
            ConsistentHash(replicas=-4)

    def test_replicas_bool_rejected(self):
        with self.assertRaises(TypeError):
            ConsistentHash(replicas=True)

    def test_replicas_str_rejected(self):
        with self.assertRaises(TypeError):
            ConsistentHash(replicas="16")


class TestAddNode(unittest.TestCase):
    def test_add_returns_point_count(self):
        ring = ConsistentHash(replicas=16)
        self.assertEqual(ring.add_node("worker-1"), 16)
        self.assertEqual(len(ring), 1)

    def test_nodes_first_added_order(self):
        ring = make_ring(8, "a", "b", "c")
        self.assertEqual(ring.nodes(), ("a", "b", "c"))

    def test_duplicate_add_fails_closed(self):
        ring = make_ring(8, "a")
        with self.assertRaises(ConsistentHashError):
            ring.add_node("a")

    def test_empty_node_id_rejected(self):
        ring = ConsistentHash()
        with self.assertRaises(ValueError):
            ring.add_node("")

    def test_non_str_node_id_rejected(self):
        ring = ConsistentHash()
        with self.assertRaises(TypeError):
            ring.add_node(123)


class TestRemoveNode(unittest.TestCase):
    def test_remove_returns_point_count(self):
        ring = make_ring(16, "a", "b")
        self.assertEqual(ring.remove_node("a"), 16)
        self.assertEqual(len(ring), 1)
        self.assertEqual(ring.nodes(), ("b",))

    def test_remove_unknown_raises_key_error(self):
        ring = make_ring(8, "a")
        with self.assertRaises(KeyError):
            ring.remove_node("ghost")

    def test_remove_non_str_rejected(self):
        ring = make_ring(8, "a")
        with self.assertRaises(TypeError):
            ring.remove_node(None)

    def test_remove_last_node_empties_ring(self):
        ring = make_ring(8, "a")
        ring.remove_node("a")
        self.assertEqual(len(ring), 0)
        with self.assertRaises(EmptyRingError):
            ring.get_node("k")


class TestRouting(unittest.TestCase):
    def test_deterministic_routing(self):
        ring = make_ring(16, "a", "b", "c")
        for key in ("session-1", "memory-seg-9", "x"):
            self.assertEqual(ring.get_node(key), ring.get_node(key))

    def test_deterministic_across_instances(self):
        r1 = make_ring(16, "a", "b", "c")
        r2 = make_ring(16, "a", "b", "c")
        keys = [f"k{i}" for i in range(50)]
        self.assertEqual(
            [r1.get_node(k) for k in keys],
            [r2.get_node(k) for k in keys],
        )

    def test_single_node_gets_everything(self):
        ring = make_ring(8, "only")
        for i in range(20):
            self.assertEqual(ring.get_node(f"k{i}"), "only")

    def test_empty_ring_fails_closed(self):
        ring = ConsistentHash()
        with self.assertRaises(EmptyRingError):
            ring.get_node("anything")

    def test_non_str_key_rejected(self):
        ring = make_ring(8, "a")
        with self.assertRaises(TypeError):
            ring.get_node(b"bytes-key")

    def test_empty_string_key_allowed(self):
        ring = make_ring(8, "a", "b")
        owner = ring.get_node("")
        self.assertIn(owner, ("a", "b"))

    def test_distribution_roughly_even(self):
        ring = make_ring(64, "a", "b", "c", "d")
        counts = {"a": 0, "b": 0, "c": 0, "d": 0}
        for i in range(2000):
            counts[ring.get_node(f"key-{i}")] += 1
        # Each of 4 nodes should hold 10%..40% (mean 25%).
        for node, count in counts.items():
            self.assertGreaterEqual(count, 200, node)
            self.assertLessEqual(count, 800, node)

    def test_add_node_moves_only_fraction(self):
        ring = make_ring(32, "a", "b", "c")
        keys = [f"key-{i}" for i in range(600)]
        before = {k: ring.get_node(k) for k in keys}
        ring.add_node("d")
        after = {k: ring.get_node(k) for k in keys}
        moved = [k for k in keys if before[k] != after[k]]
        # ~1/4 of keys move to the new node; never more than half.
        self.assertGreater(len(moved), 0)
        self.assertLess(len(moved), len(keys) // 2)
        for k in moved:
            self.assertEqual(after[k], "d")

    def test_remove_node_moves_only_removed_keys(self):
        ring = make_ring(32, "a", "b", "c")
        keys = [f"key-{i}" for i in range(600)]
        before = {k: ring.get_node(k) for k in keys}
        ring.remove_node("b")
        after = {k: ring.get_node(k) for k in keys}
        for k in keys:
            if before[k] == "b":
                self.assertNotEqual(after[k], "b")
                self.assertIn(after[k], ("a", "c"))
            else:
                self.assertEqual(after[k], before[k])


class TestGetNodes(unittest.TestCase):
    def test_replication_set_distinct_and_ordered(self):
        ring = make_ring(16, "a", "b", "c")
        owners = ring.get_nodes("key-1", 3)
        self.assertEqual(len(owners), 3)
        self.assertEqual(len(set(owners)), 3)
        self.assertEqual(owners[0], ring.get_node("key-1"))

    def test_count_one_equals_primary(self):
        ring = make_ring(16, "a", "b")
        self.assertEqual(ring.get_nodes("k", 1), (ring.get_node("k"),))

    def test_count_exceeds_nodes_rejected(self):
        ring = make_ring(8, "a", "b")
        with self.assertRaises(ValueError):
            ring.get_nodes("k", 3)

    def test_count_zero_rejected(self):
        ring = make_ring(8, "a")
        with self.assertRaises(ValueError):
            ring.get_nodes("k", 0)

    def test_empty_ring_rejected(self):
        ring = ConsistentHash()
        with self.assertRaises(EmptyRingError):
            ring.get_nodes("k", 1)


class TestSnapshotAndAudit(unittest.TestCase):
    def test_snapshot_shape(self):
        ring = make_ring(8, "a", "b")
        snap = ring.snapshot()
        self.assertIsInstance(snap, RingSnapshot)
        self.assertEqual(snap.replicas, 8)
        self.assertEqual(snap.total_points, 16)
        d = snap.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(
            d["node_counts"],
            [{"node_id": "a", "points": 8}, {"node_id": "b", "points": 8}],
        )

    def test_audit_event_add(self):
        ring = make_ring(8, "a")
        event = consistent_hash_audit_event("node-added", ring, "a", 3)
        self.assertEqual(event["event"], "consistent-hash.node-added")
        self.assertEqual(event["node_id"], "a")
        self.assertEqual(event["node_count"], 1)
        self.assertEqual(event["audit_seq"], 3)
        self.assertEqual(event["schema"], SCHEMA_PIN)

    def test_audit_event_remove(self):
        ring = make_ring(8, "a")
        event = consistent_hash_audit_event("node-removed", ring, "a", 4)
        self.assertEqual(event["event"], "consistent-hash.node-removed")

    def test_audit_event_bad_action(self):
        ring = make_ring(8, "a")
        with self.assertRaises(ValueError):
            consistent_hash_audit_event("migrate", ring, "a", 0)

    def test_audit_event_bad_seq(self):
        ring = make_ring(8, "a")
        with self.assertRaises(ValueError):
            consistent_hash_audit_event("node-added", ring, "a", -1)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        import consistent_hash as module

        self.assertIsNone(module.main())


if __name__ == "__main__":
    unittest.main()
