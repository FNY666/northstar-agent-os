"""Tests for crdt_interface.py."""

import sys
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from crdt_interface import (  # noqa: E402
    CRDT_INTERFACE_VERSION,
    SCHEMA_PIN,
    CRDTError,
    GCounter,
    PNCounter,
    crdt_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(CRDT_INTERFACE_VERSION, "crdt-interface.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.crdt-interface.v1")


class TestFrozen(unittest.TestCase):
    def test_gcounter_frozen(self):
        c = GCounter("a")
        with self.assertRaises(FrozenInstanceError):
            c.replica_id = "b"  # type: ignore[misc]

    def test_pncounter_frozen(self):
        p = PNCounter("a")
        with self.assertRaises(FrozenInstanceError):
            p.replica_id = "b"  # type: ignore[misc]


class TestGCounterConstruction(unittest.TestCase):
    def test_empty_starts_at_zero(self):
        self.assertEqual(GCounter("a").value, 0)

    def test_bad_replica_id(self):
        for bad in ("", True, 42, None, b"a"):
            with self.assertRaises(CRDTError, msg=f"replica_id={bad!r}"):
                GCounter(bad)  # type: ignore[arg-type]

    def test_bad_counts(self):
        with self.assertRaises(CRDTError):
            GCounter("a", {"a": -1})
        with self.assertRaises(CRDTError):
            GCounter("a", {"a": True})
        with self.assertRaises(CRDTError):
            GCounter("a", (("a", 1), ("a", 2)))
        with self.assertRaises(CRDTError):
            GCounter("a", "nope")  # type: ignore[arg-type]

    def test_counts_from_mapping(self):
        c = GCounter("a", {"a": 3, "b": 5})
        self.assertEqual(c.value, 8)

    def test_counts_sorted_canonical(self):
        c1 = GCounter("a", {"b": 5, "a": 3})
        c2 = GCounter("a", {"a": 3, "b": 5})
        self.assertEqual(c1.counts, c2.counts)
        self.assertEqual(hash(c1), hash(c2))


class TestGCounterIncrement(unittest.TestCase):
    def test_increment_happy_path(self):
        c = GCounter("a").increment()
        self.assertEqual(c.value, 1)

    def test_increment_by_n(self):
        c = GCounter("a").increment(7)
        self.assertEqual(c.value, 7)

    def test_increment_accumulates(self):
        c = GCounter("a").increment(2).increment(3)
        self.assertEqual(c.value, 5)

    def test_increment_is_immutable(self):
        c = GCounter("a")
        c2 = c.increment()
        self.assertEqual(c.value, 0)
        self.assertEqual(c2.value, 1)

    def test_increment_bad_n(self):
        c = GCounter("a")
        for bad in (0, -1, True, "2", 1.5, None):
            with self.assertRaises(CRDTError, msg=f"n={bad!r}"):
                c.increment(bad)  # type: ignore[arg-type]

    def test_increment_advances_only_own_entry(self):
        c = GCounter("a", {"a": 3, "b": 5}).increment(2)
        counts = dict(c.counts)
        self.assertEqual(counts, {"a": 5, "b": 5})


class TestGCounterMerge(unittest.TestCase):
    def test_merge_takes_per_replica_max(self):
        a = GCounter("a", {"a": 3, "b": 1})
        b = GCounter("b", {"a": 2, "b": 5})
        merged = a.merge(b)
        self.assertEqual(dict(merged.counts), {"a": 3, "b": 5})
        self.assertEqual(merged.value, 8)

    def test_merge_commutative(self):
        a = GCounter("a").increment(3)
        b = GCounter("b").increment(5)
        self.assertEqual(a.merge(b).counts, b.merge(a).counts)

    def test_merge_associative(self):
        a = GCounter("a").increment(1)
        b = GCounter("b").increment(2)
        c = GCounter("c").increment(3)
        self.assertEqual(a.merge(b).merge(c).counts, a.merge(b.merge(c)).counts)

    def test_merge_idempotent(self):
        a = GCounter("a").increment(4)
        self.assertEqual(a.merge(a).counts, a.counts)

    def test_merge_is_immutable(self):
        a = GCounter("a").increment(3)
        b = GCounter("b").increment(5)
        a.merge(b)
        self.assertEqual(a.value, 3)
        self.assertEqual(b.value, 5)

    def test_merge_wrong_type(self):
        with self.assertRaises(TypeError):
            GCounter("a").merge(PNCounter("a"))  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            GCounter("a").merge("nope")  # type: ignore[arg-type]


class TestPNCounterConstruction(unittest.TestCase):
    def test_default_halves_empty(self):
        p = PNCounter("a")
        self.assertEqual(p.value, 0)
        self.assertEqual(p.inc.value, 0)
        self.assertEqual(p.dec.value, 0)

    def test_bad_replica_id(self):
        for bad in ("", True, 42, None):
            with self.assertRaises(CRDTError, msg=f"replica_id={bad!r}"):
                PNCounter(bad)  # type: ignore[arg-type]

    def test_bad_halves(self):
        with self.assertRaises(CRDTError):
            PNCounter("a", inc="nope")  # type: ignore[arg-type]


class TestPNCounterOps(unittest.TestCase):
    def test_increment_decrement(self):
        p = PNCounter("a").increment(10).decrement(4)
        self.assertEqual(p.value, 6)

    def test_net_can_go_negative(self):
        p = PNCounter("a").decrement(5)
        self.assertEqual(p.value, -5)

    def test_ops_are_immutable(self):
        p = PNCounter("a")
        p.increment(3)
        self.assertEqual(p.value, 0)

    def test_bad_amounts(self):
        p = PNCounter("a")
        for bad in (0, -2, True, "3", None):
            with self.assertRaises(CRDTError, msg=f"n={bad!r}"):
                p.increment(bad)  # type: ignore[arg-type]
            with self.assertRaises(CRDTError, msg=f"n={bad!r}"):
                p.decrement(bad)  # type: ignore[arg-type]


class TestPNCounterMerge(unittest.TestCase):
    def test_merge_both_halves(self):
        p1 = PNCounter("a").increment(10).decrement(4)
        p2 = PNCounter("b").increment(7).decrement(2)
        merged = p1.merge(p2)
        self.assertEqual(merged.value, (10 + 7) - (4 + 2))

    def test_merge_commutative(self):
        p1 = PNCounter("a").increment(10).decrement(4)
        p2 = PNCounter("b").increment(7).decrement(2)
        self.assertEqual(p1.merge(p2).value, p2.merge(p1).value)

    def test_merge_idempotent(self):
        p = PNCounter("a").increment(5).decrement(2)
        self.assertEqual(p.merge(p).value, p.value)

    def test_merge_wrong_type(self):
        with self.assertRaises(TypeError):
            PNCounter("a").merge(GCounter("a"))  # type: ignore[arg-type]


class TestRecords(unittest.TestCase):
    def test_gcounter_as_dict(self):
        d = GCounter("a", {"a": 3}).as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["kind"], "gcounter")
        self.assertEqual(d["value"], 3)

    def test_pncounter_as_dict(self):
        d = PNCounter("a").increment(4).decrement(1).as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["kind"], "pncounter")
        self.assertEqual(d["value"], 3)

    def test_audit_event_shape(self):
        ev = crdt_audit_event("increment", GCounter("a").increment(), seq=2)
        self.assertEqual(ev["event"], "crdt")
        self.assertEqual(ev["kind"], "increment")
        self.assertEqual(ev["audit_seq"], 2)
        self.assertEqual(ev["schema"], SCHEMA_PIN)

    def test_audit_event_bad_kind(self):
        with self.assertRaises(CRDTError):
            crdt_audit_event("explode", GCounter("a"), seq=0)

    def test_audit_event_bad_seq(self):
        c = GCounter("a")
        for bad in (-1, True, "1", None):
            with self.assertRaises(CRDTError, msg=f"seq={bad!r}"):
                crdt_audit_event("merge", c, seq=bad)  # type: ignore[arg-type]

    def test_audit_event_bad_counter(self):
        with self.assertRaises(TypeError):
            crdt_audit_event("merge", {"value": 1}, seq=0)  # type: ignore[arg-type]


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        import crdt_interface

        crdt_interface.main()  # must not raise


if __name__ == "__main__":
    unittest.main()
