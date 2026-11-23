"""Tests for the separation-logic interface (house style)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from separation_logic import (
    SEPARATION_LOGIC_SCHEMA,
    SEPARATION_LOGIC_VERSION,
    FramedTriple,
    HeapAssertion,
    SepLogic,
    SepLogicError,
    separation_logic_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(SEPARATION_LOGIC_VERSION, "separation-logic.v1")
        self.assertEqual(SEPARATION_LOGIC_SCHEMA, "northstar.separation-logic.v1")

    def test_schema_on_records(self):
        sl = SepLogic()
        self.assertEqual(sl.emp().as_dict()["schema"], SEPARATION_LOGIC_SCHEMA)


class TestEmp(unittest.TestCase):
    def setUp(self):
        self.sl = SepLogic()

    def test_emp_digest_deterministic(self):
        self.assertEqual(self.sl.emp().digest, self.sl.emp().digest)

    def test_emp_empty_footprint(self):
        self.assertEqual(self.sl.footprint(self.sl.emp()), frozenset())

    def test_emp_as_dict(self):
        d = self.sl.emp().as_dict()
        self.assertEqual(d["kind"], "emp")
        self.assertTrue(d["digest"].startswith("sha256:"))


class TestPointsTo(unittest.TestCase):
    def setUp(self):
        self.sl = SepLogic()

    def test_deterministic(self):
        a = self.sl.points_to(0, b"v")
        b = self.sl.points_to(0, b"v")
        self.assertEqual(a.digest, b.digest)

    def test_addr_sensitive(self):
        self.assertNotEqual(
            self.sl.points_to(0, b"v").digest, self.sl.points_to(1, b"v").digest
        )

    def test_value_sensitive(self):
        self.assertNotEqual(
            self.sl.points_to(0, b"v").digest, self.sl.points_to(0, b"w").digest
        )

    def test_footprint_singleton(self):
        self.assertEqual(self.sl.footprint(self.sl.points_to(3, b"x")), frozenset({3}))

    def test_bool_addr_rejected(self):
        with self.assertRaises(SepLogicError):
            self.sl.points_to(True, b"v")

    def test_negative_addr_rejected(self):
        with self.assertRaises(SepLogicError):
            self.sl.points_to(-1, b"v")

    def test_str_value_rejected(self):
        with self.assertRaises(SepLogicError):
            self.sl.points_to(0, "v")  # type: ignore[arg-type]

    def test_as_dict_shape(self):
        d = self.sl.points_to(2, b"q").as_dict()
        self.assertEqual(d["kind"], "points_to")
        self.assertEqual(d["addr"], 2)
        self.assertTrue(d["value_pin"].startswith("sha256:"))


class TestStar(unittest.TestCase):
    def setUp(self):
        self.sl = SepLogic()

    def test_disjoint_composes(self):
        ab = self.sl.star(self.sl.points_to(0, b"a"), self.sl.points_to(1, b"b"))
        self.assertEqual(ab.kind, "star")
        self.assertEqual(self.sl.footprint(ab), frozenset({0, 1}))

    def test_commutative_normalization(self):
        a = self.sl.points_to(0, b"a")
        b = self.sl.points_to(1, b"b")
        self.assertEqual(self.sl.star(a, b).digest, self.sl.star(b, a).digest)

    def test_overlap_fails_closed(self):
        a = self.sl.points_to(0, b"a")
        with self.assertRaises(SepLogicError):
            self.sl.star(a, self.sl.points_to(0, b"other"))

    def test_nested_overlap_fails(self):
        inner = self.sl.star(self.sl.points_to(0, b"a"), self.sl.points_to(1, b"b"))
        with self.assertRaises(SepLogicError):
            self.sl.star(inner, self.sl.points_to(1, b"c"))

    def test_non_assertion_rejected(self):
        with self.assertRaises(SepLogicError):
            self.sl.star(self.sl.emp(), "nope")  # type: ignore[arg-type]

    def test_star_all_empty_is_emp(self):
        self.assertEqual(self.sl.star_all(()).digest, self.sl.emp().digest)

    def test_star_all_folds(self):
        acc = self.sl.star_all(
            (self.sl.points_to(0, b"a"), self.sl.points_to(2, b"c"))
        )
        self.assertEqual(self.sl.footprint(acc), frozenset({0, 2}))

    def test_star_all_overlap_fails(self):
        with self.assertRaises(SepLogicError):
            self.sl.star_all(
                (self.sl.points_to(0, b"a"), self.sl.points_to(0, b"b"))
            )


class TestPure(unittest.TestCase):
    def setUp(self):
        self.sl = SepLogic()

    def test_pure_empty_footprint(self):
        self.assertEqual(self.sl.footprint(self.sl.pure("x > 0")), frozenset())

    def test_pure_empty_name_rejected(self):
        with self.assertRaises(SepLogicError):
            self.sl.pure("")

    def test_pure_non_str_rejected(self):
        with self.assertRaises(SepLogicError):
            self.sl.pure(5)  # type: ignore[arg-type]


class TestEntails(unittest.TestCase):
    def setUp(self):
        self.sl = SepLogic()

    def test_reflexive(self):
        a = self.sl.points_to(0, b"a")
        self.assertTrue(self.sl.entails(a, a))

    def test_pure_strips(self):
        a = self.sl.points_to(0, b"a")
        self.assertTrue(self.sl.entails(self.sl.star(a, self.sl.pure("q")), a))

    def test_distinct_not_entailed(self):
        a = self.sl.points_to(0, b"a")
        b = self.sl.points_to(1, b"b")
        self.assertFalse(self.sl.entails(a, b))

    def test_star_rearrangement_entailed(self):
        a = self.sl.points_to(0, b"a")
        b = self.sl.points_to(1, b"b")
        self.assertTrue(self.sl.entails(self.sl.star(a, b), self.sl.star(b, a)))

    def test_emp_entails_only_emp(self):
        a = self.sl.points_to(0, b"a")
        self.assertTrue(self.sl.entails(self.sl.emp(), self.sl.emp()))
        self.assertFalse(self.sl.entails(self.sl.emp(), a))


class TestFrameRule(unittest.TestCase):
    def setUp(self):
        self.sl = SepLogic()

    def test_frames_both_sides(self):
        pre = self.sl.points_to(0, b"old")
        post = self.sl.points_to(0, b"new")
        frame = self.sl.points_to(9, b"untouched")
        ft = self.sl.frame_rule(pre, post, frame)
        self.assertIsInstance(ft, FramedTriple)
        self.assertEqual(self.sl.footprint(ft.pre), frozenset({0, 9}))
        self.assertEqual(self.sl.footprint(ft.post), frozenset({0, 9}))
        self.assertTrue(ft.digest.startswith("sha256:"))

    def test_frame_overlap_pre_fails(self):
        pre = self.sl.points_to(0, b"old")
        post = self.sl.points_to(0, b"new")
        with self.assertRaises(SepLogicError):
            self.sl.frame_rule(pre, post, self.sl.points_to(0, b"clash"))

    def test_frame_overlap_post_fails(self):
        pre = self.sl.points_to(0, b"old")
        post = self.sl.points_to(5, b"new")
        with self.assertRaises(SepLogicError):
            self.sl.frame_rule(pre, post, self.sl.points_to(5, b"clash"))

    def test_frame_deterministic(self):
        pre = self.sl.points_to(0, b"old")
        post = self.sl.points_to(0, b"new")
        frame = self.sl.points_to(9, b"u")
        self.assertEqual(
            self.sl.frame_rule(pre, post, frame).digest,
            self.sl.frame_rule(pre, post, frame).digest,
        )

    def test_non_assertion_rejected(self):
        with self.assertRaises(SepLogicError):
            self.sl.frame_rule(self.sl.emp(), self.sl.emp(), None)  # type: ignore[arg-type]

    def test_as_dict_shape(self):
        pre = self.sl.points_to(0, b"old")
        post = self.sl.points_to(0, b"new")
        frame = self.sl.points_to(9, b"u")
        d = self.sl.frame_rule(pre, post, frame).as_dict()
        self.assertEqual(d["schema"], SEPARATION_LOGIC_SCHEMA)
        self.assertIn("pre", d)
        self.assertIn("post", d)
        self.assertIn("frame", d)


class TestAuditEvent(unittest.TestCase):
    def test_shape(self):
        sl = SepLogic()
        ev = separation_logic_audit_event(
            "frame-applied", 7, sl.points_to(0, b"a"), detail="t1"
        )
        self.assertEqual(ev["schema"], SEPARATION_LOGIC_SCHEMA)
        self.assertEqual(ev["kind"], "frame-applied")
        self.assertEqual(ev["seq"], 7)
        self.assertTrue(ev["assertion_digest"].startswith("sha256:"))

    def test_none_assertion_ok(self):
        ev = separation_logic_audit_event("rejected", 0)
        self.assertEqual(ev["assertion_digest"], "")

    def test_unknown_kind_rejected(self):
        with self.assertRaises(SepLogicError):
            separation_logic_audit_event("bogus", 0)

    def test_bad_seq_rejected(self):
        with self.assertRaises(SepLogicError):
            separation_logic_audit_event("rejected", True)  # type: ignore[arg-type]


class TestHeapAssertionValidation(unittest.TestCase):
    def test_unknown_kind_rejected(self):
        with self.assertRaises(SepLogicError):
            HeapAssertion(kind="bogus", digest="sha256:x")

    def test_missing_digest_rejected(self):
        with self.assertRaises(SepLogicError):
            HeapAssertion(kind="emp", digest="")

    def test_frozen(self):
        a = SepLogic().emp()
        with self.assertRaises(Exception):
            a.kind = "star"  # type: ignore[misc]

    def test_main_self_check(self):
        import separation_logic

        separation_logic.main()  # must not raise


if __name__ == "__main__":
    unittest.main()
