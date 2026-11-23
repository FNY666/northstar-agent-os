"""Tests for crdt_set.py."""

import json
import subprocess
import sys
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from crdt_set import (  # noqa: E402
    CRDT_SET_VERSION,
    SCHEMA_PIN,
    CRDTSet,
    CRDTSetError,
    crdt_set_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(CRDT_SET_VERSION, "crdt-set.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.crdt-set.v1")


class TestFrozen(unittest.TestCase):
    def test_set_is_frozen(self):
        s = CRDTSet("a")
        with self.assertRaises(FrozenInstanceError):
            s.clock = 5  # type: ignore[misc]


class TestConstruction(unittest.TestCase):
    def test_empty_set(self):
        s = CRDTSet("a")
        self.assertEqual(s.elements, ())
        self.assertFalse(s.contains("x"))

    def test_bad_replica_ids(self):
        for bad in ("", True, False, None, 123, b"a"):
            with self.assertRaises(CRDTSetError):
                CRDTSet(bad)  # type: ignore[arg-type]

    def test_duplicate_pairs_rejected(self):
        with self.assertRaises(CRDTSetError):
            CRDTSet("a", adds=(("x", "t1"), ("x", "t1")))

    def test_bad_clock(self):
        with self.assertRaises(CRDTSetError):
            CRDTSet("a", clock=-1)
        with self.assertRaises(CRDTSetError):
            CRDTSet("a", clock=True)  # type: ignore[arg-type]


class TestAddRemove(unittest.TestCase):
    def test_add_makes_present(self):
        s = CRDTSet("a").add("x")
        self.assertTrue(s.contains("x"))
        self.assertEqual(s.elements, ("x",))

    def test_auto_tags_are_unique_and_clock_advances(self):
        s = CRDTSet("a").add("x").add("y")
        tags = [t for _, t in s.adds]
        self.assertEqual(len(set(tags)), 2)
        self.assertEqual(s.clock, 2)
        self.assertTrue(all(t.startswith("a:") for t in tags))

    def test_explicit_tag(self):
        s = CRDTSet("a").add("x", tag="ext-1")
        self.assertIn(("x", "ext-1"), s.adds)
        self.assertTrue(s.contains("x"))

    def test_bad_elements_and_tags(self):
        s = CRDTSet("a")
        for bad in ("", True, None, 42):
            with self.assertRaises(CRDTSetError):
                s.add(bad)  # type: ignore[arg-type]
            with self.assertRaises(CRDTSetError):
                s.remove(bad)  # type: ignore[arg-type]
            with self.assertRaises(CRDTSetError):
                s.contains(bad)  # type: ignore[arg-type]
        with self.assertRaises(CRDTSetError):
            s.add("x", tag="")

    def test_remove_makes_absent(self):
        s = CRDTSet("a").add("x").remove("x")
        self.assertFalse(s.contains("x"))
        self.assertEqual(s.elements, ())

    def test_remove_unknown_is_noop(self):
        s = CRDTSet("a").add("x")
        self.assertIs(s.remove("nope"), s)

    def test_readd_after_remove(self):
        s = CRDTSet("a").add("x").remove("x").add("x")
        self.assertTrue(s.contains("x"))  # fresh tag, not tombstoned


class TestMerge(unittest.TestCase):
    def test_merge_unions_elements(self):
        a = CRDTSet("a").add("x")
        b = CRDTSet("b").add("y")
        merged = a.merge(b)
        self.assertEqual(merged.elements, ("x", "y"))

    def test_merge_commutative_on_payload(self):
        a = CRDTSet("a").add("x").add("y")
        b = CRDTSet("b").add("y", tag="b:9").add("z")
        ab, ba = a.merge(b), b.merge(a)
        self.assertEqual(ab.elements, ba.elements)
        self.assertEqual(set(ab.adds), set(ba.adds))
        self.assertEqual(set(ab.tombstones), set(ba.tombstones))

    def test_merge_idempotent(self):
        a = CRDTSet("a").add("x").remove("x")
        m = a.merge(a)
        self.assertEqual(m.elements, a.elements)
        self.assertEqual(set(m.adds), set(a.adds))

    def test_merge_associative_on_payload(self):
        a = CRDTSet("a").add("x")
        b = CRDTSet("b").add("y").remove("y")
        c = CRDTSet("c").add("z")
        left = a.merge(b).merge(c)
        right = a.merge(b.merge(c))
        self.assertEqual(left.elements, right.elements)
        self.assertEqual(set(left.adds), set(right.adds))
        self.assertEqual(set(left.tombstones), set(right.tombstones))

    def test_merge_takes_max_clock(self):
        a = CRDTSet("a").add("x").add("y")  # clock 2
        b = CRDTSet("b").add("z")  # clock 1
        self.assertEqual(a.merge(b).clock, 2)
        self.assertEqual(b.merge(a).clock, 2)

    def test_observed_remove_wins(self):
        a = CRDTSet("a").add("x")
        b = a.merge(CRDTSet("b"))  # b observes the add-tag
        removed = b.remove("x")
        self.assertFalse(removed.merge(a).contains("x"))

    def test_concurrent_add_survives_remove(self):
        a = CRDTSet("a").add("x").remove("x")  # tombstones a's tag
        b = CRDTSet("b").add("x")  # b's tag never observed by a
        self.assertTrue(a.merge(b).contains("x"))  # add-wins

    def test_merge_type_error(self):
        with self.assertRaises(TypeError):
            CRDTSet("a").merge("nope")  # type: ignore[arg-type]

    def test_merge_keeps_self_replica_id(self):
        merged = CRDTSet("a").add("x").merge(CRDTSet("b").add("y"))
        self.assertEqual(merged.replica_id, "a")


class TestViews(unittest.TestCase):
    def test_as_dict_json_safe(self):
        s = CRDTSet("a").add("x").remove("x")
        record = s.as_dict()
        self.assertEqual(record["schema"], SCHEMA_PIN)
        self.assertEqual(json.loads(json.dumps(record)), record)
        self.assertEqual(record["elements"], [])

    def test_elements_sorted(self):
        s = CRDTSet("a").add("z").add("m").add("a")
        self.assertEqual(s.elements, ("a", "m", "z"))


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        s = CRDTSet("a").add("x")
        for kind in ("add", "remove", "merge"):
            ev = crdt_set_audit_event(kind, s, seq=3)
            self.assertEqual(ev["event"], "crdt-set")
            self.assertEqual(ev["kind"], kind)
            self.assertEqual(ev["audit_seq"], 3)
            self.assertEqual(ev["schema"], SCHEMA_PIN)

    def test_audit_bad_kind(self):
        with self.assertRaises(CRDTSetError):
            crdt_set_audit_event("bogus", CRDTSet("a"), seq=1)

    def test_audit_bad_seq(self):
        s = CRDTSet("a")
        for bad in (-1, True, "1", None):
            with self.assertRaises(CRDTSetError):
                crdt_set_audit_event("add", s, seq=bad)  # type: ignore[arg-type]

    def test_audit_bad_set(self):
        with self.assertRaises(TypeError):
            crdt_set_audit_event("add", "nope", seq=1)  # type: ignore[arg-type]


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        module = Path(__file__).resolve().parents[1] / "crdt_set.py"
        proc = subprocess.run(
            [sys.executable, str(module)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("crdt-set OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
