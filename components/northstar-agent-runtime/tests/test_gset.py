"""Tests for gset.py (Grow-only Set CRDT)."""

import ast
import os
import subprocess
import sys
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gset import (  # noqa: E402
    AUDIT_FORMAT,
    GSET_VERSION,
    SCHEMA_PIN,
    GSet,
    GSetError,
    gset_audit_event,
)

MODULE_PATH = os.path.join(os.path.dirname(__file__), "..", "gset.py")


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(GSET_VERSION, "gset.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.gset.v1")

    def test_audit_format_pin(self):
        self.assertEqual(AUDIT_FORMAT, "audit.ndjson/1")


class TestStdlibOnly(unittest.TestCase):
    def test_stdlib_only(self):
        tree = ast.parse(open(MODULE_PATH).read())
        allowed = {
            "hashlib", "dataclasses", "typing", "__future__",
            "ast", "json", "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed, a.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(node.module.split(".")[0], allowed, node.module)


class TestFrozen(unittest.TestCase):
    def test_gset_frozen(self):
        s = GSet("a")
        with self.assertRaises(FrozenInstanceError):
            s.replica_id = "b"  # type: ignore[misc]

    def test_elements_tuple_immutable(self):
        s = GSet("a").add("x")
        with self.assertRaises(AttributeError):
            s.elements += ("y",)  # type: ignore[misc]


class TestConstruction(unittest.TestCase):
    def test_empty_set(self):
        s = GSet("a")
        self.assertEqual(len(s), 0)
        self.assertEqual(s.elements, ())
        self.assertFalse(s.contains("x"))

    def test_elements_normalized(self):
        s = GSet("a", ("b", "a", "b", "c"))
        self.assertEqual(s.elements, ("a", "b", "c"))  # sorted + deduped

    def test_elements_from_list(self):
        s = GSet("a", ["c", "a"])
        self.assertEqual(s.elements, ("a", "c"))

    def test_bad_replica_id(self):
        for bad in ("", True, 42, None, b"a"):
            with self.assertRaises(GSetError, msg=f"replica_id={bad!r}"):
                GSet(bad)  # type: ignore[arg-type]

    def test_bad_elements(self):
        with self.assertRaises(GSetError):
            GSet("a", 42)  # type: ignore[arg-type]
        with self.assertRaises(GSetError):
            GSet("a", "nope")  # a bare str is not an iterable-of-str
        with self.assertRaises(GSetError):
            GSet("a", ("x", 1))  # type: ignore[list-item]
        with self.assertRaises(GSetError):
            GSet("a", ("x", True))  # type: ignore[list-item]
        with self.assertRaises(GSetError):
            GSet("a", ("x" * 5000,))  # oversized element

    def test_empty_string_element_allowed(self):
        s = GSet("a").add("")
        self.assertTrue(s.contains(""))


class TestAdd(unittest.TestCase):
    def test_add_roundtrip(self):
        s = GSet("a").add("x")
        self.assertTrue(s.contains("x"))
        self.assertEqual(s.elements, ("x",))

    def test_add_returns_new(self):
        s = GSet("a")
        grown = s.add("x")
        self.assertIsNot(s, grown)
        self.assertFalse(s.contains("x"))
        self.assertTrue(grown.contains("x"))

    def test_add_duplicate_is_noop(self):
        s = GSet("a").add("x")
        again = s.add("x")
        self.assertEqual(again.elements, s.elements)
        self.assertEqual(again.digest, s.digest)

    def test_add_bad_element(self):
        s = GSet("a")
        for bad in (1, True, None, b"x"):
            with self.assertRaises(GSetError, msg=f"element={bad!r}"):
                s.add(bad)  # type: ignore[arg-type]

    def test_add_all(self):
        s = GSet("a").add_all(["c", "a", "b", "a"])
        self.assertEqual(s.elements, ("a", "b", "c"))

    def test_add_all_empty(self):
        s = GSet("a").add_all([])
        self.assertEqual(len(s), 0)

    def test_add_all_bad(self):
        s = GSet("a")
        with self.assertRaises(GSetError):
            s.add_all(42)  # type: ignore[arg-type]
        with self.assertRaises(GSetError):
            s.add_all(["ok", 7])  # type: ignore[list-item]


class TestMerge(unittest.TestCase):
    def test_merge_union(self):
        a = GSet("a").add_all(["x", "y"])
        b = GSet("b").add_all(["y", "z"])
        self.assertEqual(a.merge(b).elements, ("x", "y", "z"))

    def test_merge_commutative(self):
        a = GSet("a").add_all(["x", "y"])
        b = GSet("b").add_all(["y", "z"])
        self.assertEqual(a.merge(b).elements, b.merge(a).elements)
        self.assertEqual(a.merge(b).digest, b.merge(a).digest)

    def test_merge_associative(self):
        a = GSet("a").add("x")
        b = GSet("b").add("y")
        c = GSet("c").add("z")
        self.assertEqual(
            a.merge(b).merge(c).elements, a.merge(b.merge(c)).elements
        )

    def test_merge_idempotent(self):
        a = GSet("a").add_all(["x", "y"])
        self.assertEqual(a.merge(a).elements, a.elements)

    def test_merge_wrong_type(self):
        a = GSet("a")
        with self.assertRaises(TypeError):
            a.merge({"x"})  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            a.merge("x")  # type: ignore[arg-type]


class TestMembership(unittest.TestCase):
    def test_contains(self):
        s = GSet("a").add("x")
        self.assertTrue(s.contains("x"))
        self.assertFalse(s.contains("y"))

    def test_contains_bad_type(self):
        s = GSet("a")
        with self.assertRaises(GSetError):
            s.contains(1)  # type: ignore[arg-type]

    def test_dunder_contains(self):
        s = GSet("a").add("x")
        self.assertIn("x", s)
        self.assertNotIn("y", s)

    def test_len_and_iter(self):
        s = GSet("a").add_all(["c", "a", "b"])
        self.assertEqual(len(s), 3)
        self.assertEqual(list(s), ["a", "b", "c"])  # sorted iteration


class TestSubset(unittest.TestCase):
    def test_issubset(self):
        a = GSet("a").add_all(["x", "y"])
        b = GSet("b").add_all(["x", "y", "z"])
        self.assertTrue(a.issubset(b))
        self.assertFalse(b.issubset(a))
        self.assertTrue(a.issubset(a))

    def test_issubset_wrong_type(self):
        a = GSet("a")
        with self.assertRaises(TypeError):
            a.issubset(["x"])  # type: ignore[arg-type]


class TestDigest(unittest.TestCase):
    def test_digest_deterministic(self):
        a = GSet("a").add_all(["x", "y"])
        b = GSet("b").add_all(["y", "x"])  # different order, different replica
        self.assertEqual(a.digest, b.digest)  # replica-agnostic

    def test_digest_differs(self):
        a = GSet("a").add("x")
        b = GSet("a").add("y")
        self.assertNotEqual(a.digest, b.digest)

    def test_digest_shape(self):
        s = GSet("a").add("x")
        self.assertTrue(s.digest.startswith("sha256:"))
        self.assertEqual(len(s.digest), len("sha256:") + 64)

    def test_verify(self):
        s = GSet("a").add_all(["x", "y"])
        self.assertTrue(s.verify())

    def test_digest_cross_instance(self):
        # Same membership built on a fresh instance: identical digest.
        a = GSet("r1").add_all(["m", "n"])
        b = GSet("r2")
        for el in ("n", "m"):
            b = b.add(el)
        self.assertEqual(a.digest, b.digest)


class TestAudit(unittest.TestCase):
    def test_add_event_shape(self):
        s = GSet("a").add("x")
        ev = gset_audit_event("add", s, seq=3)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["event"], "gset")
        self.assertEqual(ev["kind"], "add")
        self.assertEqual(ev["module"], "gset.v1")
        self.assertEqual(ev["replica_id"], "a")
        self.assertEqual(ev["digest"], s.digest)
        self.assertEqual(ev["size"], 1)
        self.assertEqual(ev["audit_seq"], 3)

    def test_merge_event_shape(self):
        s = GSet("a").add_all(["x", "y"]).merge(GSet("b").add("z"))
        ev = gset_audit_event("merge", s, seq=0)
        self.assertEqual(ev["kind"], "merge")
        self.assertEqual(ev["size"], 3)
        self.assertEqual(ev["audit_seq"], 0)

    def test_element_values_banned(self):
        s = GSet("a").add("secret-capability")
        ev = gset_audit_event("add", s, seq=1)
        blob = str(ev)
        self.assertNotIn("secret-capability", blob)

    def test_bad_kind(self):
        s = GSet("a")
        with self.assertRaises(GSetError):
            gset_audit_event("delete", s, seq=1)

    def test_bad_seq(self):
        s = GSet("a")
        for bad in (-1, True, 1.5, "1"):
            with self.assertRaises(GSetError, msg=f"seq={bad!r}"):
                gset_audit_event("add", s, seq=bad)  # type: ignore[arg-type]

    def test_bad_gset_type(self):
        with self.assertRaises(TypeError):
            gset_audit_event("add", "nope", seq=1)  # type: ignore[arg-type]


class TestMain(unittest.TestCase):
    def test_main_subprocess(self):
        r = subprocess.run(
            [sys.executable, MODULE_PATH],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("gset OK", r.stdout)


if __name__ == "__main__":
    unittest.main()
