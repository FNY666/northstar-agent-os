"""Tests for abstract_interp: interval domain + fixpoint analyzer."""

import math
import unittest

from abstract_interp import (
    ABSTRACT_INTERP_SCHEMA,
    ABSTRACT_INTERP_VERSION,
    AbstractInterp,
    AbstractInterpError,
    AnalysisResult,
    BottomError,
    DivisionByZeroError,
    Interval,
    abstract_interp_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_and_schema(self):
        self.assertEqual(ABSTRACT_INTERP_VERSION, "abstract-interp.v1")
        self.assertEqual(ABSTRACT_INTERP_SCHEMA, "northstar.abstract-interp.v1")

    def test_main_module_imports(self):
        import abstract_interp
        self.assertTrue(hasattr(abstract_interp, "main"))


class TestIntervalConstruction(unittest.TestCase):
    def test_const_and_top(self):
        i = Interval.const(5)
        self.assertEqual((i.lo, i.hi), (5.0, 5.0))
        self.assertFalse(i.is_bottom())
        self.assertTrue(Interval.top().is_top())

    def test_empty_is_bottom(self):
        b = Interval.empty()
        self.assertTrue(b.is_bottom())
        self.assertFalse(b.is_top())

    def test_bool_rejected(self):
        with self.assertRaises(TypeError):
            Interval.const(True)
        with self.assertRaises(TypeError):
            Interval(lo=True, hi=1)

    def test_nan_rejected(self):
        with self.assertRaises(ValueError):
            Interval.const(float("nan"))

    def test_lo_gt_hi_rejected(self):
        with self.assertRaises(ValueError):
            Interval(lo=3, hi=2)

    def test_infinite_ends_allowed(self):
        i = Interval(lo=-math.inf, hi=math.inf)
        self.assertTrue(i.is_top())

    def test_contains(self):
        i = Interval(lo=1, hi=3)
        self.assertTrue(i.contains(2))
        self.assertFalse(i.contains(4))
        self.assertFalse(Interval.empty().contains(2))

    def test_width_and_bottom_width(self):
        self.assertEqual(Interval(lo=1, hi=4).width(), 3.0)
        self.assertEqual(Interval.top().width(), math.inf)
        with self.assertRaises(BottomError):
            Interval.empty().width()

    def test_as_dict(self):
        d = Interval(lo=1, hi=2).as_dict()
        self.assertEqual(d["schema"], ABSTRACT_INTERP_SCHEMA)
        self.assertEqual(d["version"], ABSTRACT_INTERP_VERSION)
        self.assertEqual((d["lo"], d["hi"]), (1.0, 2.0))
        self.assertFalse(d["bottom"])


class TestLatticeOps(unittest.TestCase):
    def test_join_hull(self):
        j = Interval(lo=1, hi=2).join(Interval(lo=5, hi=7))
        self.assertEqual((j.lo, j.hi), (1.0, 7.0))

    def test_join_bottom_identity(self):
        i = Interval(lo=1, hi=2)
        self.assertEqual(i.join(Interval.empty()), i)
        self.assertEqual(Interval.empty().join(i), i)

    def test_meet_intersection(self):
        m = Interval(lo=1, hi=5).meet(Interval(lo=3, hi=8))
        self.assertEqual((m.lo, m.hi), (3.0, 5.0))

    def test_meet_disjoint_is_bottom(self):
        m = Interval(lo=1, hi=2).meet(Interval(lo=5, hi=6))
        self.assertTrue(m.is_bottom())

    def test_leq(self):
        self.assertTrue(Interval(lo=2, hi=3).leq(Interval(lo=1, hi=5)))
        self.assertFalse(Interval(lo=1, hi=5).leq(Interval(lo=2, hi=3)))
        self.assertTrue(Interval.empty().leq(Interval(lo=1, hi=2)))
        self.assertFalse(Interval(lo=1, hi=2).leq(Interval.empty()))

    def test_widen_grows_to_infinity(self):
        w = Interval(lo=0, hi=5).widen(Interval(lo=-1, hi=9))
        self.assertEqual((w.lo, w.hi), (-math.inf, math.inf))

    def test_widen_stable_when_shrinking(self):
        w = Interval(lo=0, hi=10).widen(Interval(lo=2, hi=7))
        self.assertEqual((w.lo, w.hi), (0.0, 10.0))

    def test_narrow_recovers_precision(self):
        n = Interval(lo=0, hi=math.inf).narrow(Interval(lo=0, hi=8))
        self.assertEqual((n.lo, n.hi), (0.0, 8.0))

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            Interval(lo=1, hi=2).join("x")
        with self.assertRaises(TypeError):
            Interval(lo=1, hi=2).meet(None)


class TestTransferFunctions(unittest.TestCase):
    def test_add_sub(self):
        self.assertEqual(
            (Interval(lo=1, hi=2).add(Interval(lo=10, hi=20)).lo,
             Interval(lo=1, hi=2).add(Interval(lo=10, hi=20)).hi),
            (11.0, 22.0),
        )
        s = Interval(lo=1, hi=2).sub(Interval(lo=10, hi=20))
        self.assertEqual((s.lo, s.hi), (-19.0, -8.0))

    def test_mul_signs(self):
        m = Interval(lo=-2, hi=3).mul(Interval(lo=-4, hi=-1))
        self.assertEqual((m.lo, m.hi), (-12.0, 8.0))

    def test_div_ok(self):
        d = Interval(lo=6, hi=12).div(Interval(lo=2, hi=3))
        self.assertEqual((d.lo, d.hi), (2.0, 6.0))

    def test_div_by_zero_interval_raises(self):
        with self.assertRaises(DivisionByZeroError):
            Interval(lo=1, hi=2).div(Interval(lo=-1, hi=1))

    def test_neg(self):
        n = Interval(lo=1, hi=5).neg()
        self.assertEqual((n.lo, n.hi), (-5.0, -1.0))

    def test_bottom_propagates(self):
        b = Interval.empty()
        i = Interval(lo=1, hi=2)
        self.assertTrue(b.add(i).is_bottom())
        self.assertTrue(i.mul(b).is_bottom())
        self.assertTrue(b.div(i).is_bottom())

    def test_soundness_spot_check(self):
        # every concrete pair's product lies inside the abstract product
        a = Interval(lo=-2, hi=3)
        b = Interval(lo=4, hi=5)
        p = a.mul(b)
        for x in (-2, 0, 3):
            for y in (4, 5):
                self.assertTrue(p.contains(x * y))


class TestAnalyzer(unittest.TestCase):
    def test_straight_line(self):
        ai = AbstractInterp()
        r = ai.analyze([
            ("assign", "x", ("const", 3)),
            ("assign", "y", ("add", ("var", "x"), ("const", 4))),
        ])
        self.assertIsInstance(r, AnalysisResult)
        self.assertEqual((r.get("y").lo, r.get("y").hi), (7.0, 7.0))

    def test_unknown_var_is_top(self):
        ai = AbstractInterp()
        r = ai.analyze([("assign", "x", ("add", ("var", "undef"), ("const", 1)))])
        self.assertTrue(r.get("x").is_top())

    def test_assume_refines(self):
        ai = AbstractInterp()
        r = ai.analyze([
            ("assign", "x", ("const", 10)),
            ("assume", "x", "<", 5),
        ])
        self.assertTrue(r.get("x").is_bottom())

    def test_loop_terminates_and_is_sound(self):
        ai = AbstractInterp()
        r = ai.analyze([
            ("assign", "n", ("const", 5)),
            ("assign", "x", ("const", 0)),
            ("while", "n", [
                ("assign", "x", ("add", ("var", "x"), ("const", 1))),
                ("assign", "n", ("sub", ("var", "n"), ("const", 1))),
            ]),
        ])
        self.assertTrue(r.widened)
        self.assertTrue(r.get("x").contains(5))  # concrete answer is inside
        self.assertTrue(r.get("n").contains(0))

    def test_loop_without_growth_needs_no_widen(self):
        ai = AbstractInterp(widen_after=100)
        r = ai.analyze([
            ("assign", "n", ("const", 1)),
            ("while", "n", [("assign", "n", ("const", 0))]),
        ])
        self.assertFalse(r.widened)
        self.assertTrue(r.get("n").contains(0))

    def test_explicit_widen_narrow(self):
        ai = AbstractInterp()
        w = ai.widen(Interval(lo=0, hi=3), Interval(lo=0, hi=5))
        self.assertEqual(w.hi, math.inf)
        n = ai.narrow(Interval(lo=0, hi=math.inf), Interval(lo=0, hi=4))
        self.assertEqual(n.hi, 4.0)
        with self.assertRaises(TypeError):
            ai.widen(Interval(lo=0, hi=1), "x")

    def test_division_by_zero_in_program_raises(self):
        ai = AbstractInterp()
        with self.assertRaises(DivisionByZeroError):
            ai.analyze([("assign", "x", ("div", ("const", 1), ("const", 0)))])

    def test_bad_program_rejected(self):
        ai = AbstractInterp()
        with self.assertRaises(TypeError):
            ai.analyze("not a list")
        with self.assertRaises(ValueError):
            ai.analyze([("bogus",)])
        with self.assertRaises(ValueError):
            ai.analyze([("assign", "x", ("bogus-op",))])

    def test_result_as_dict(self):
        ai = AbstractInterp()
        r = ai.analyze([("assign", "x", ("const", 1))])
        d = r.as_dict()
        self.assertEqual(d["schema"], ABSTRACT_INTERP_SCHEMA)
        self.assertIn("x", d["env"])
        self.assertIsInstance(d["iterations"], int)

    def test_constructor_validation(self):
        with self.assertRaises(ValueError):
            AbstractInterp(widen_after=-1)
        with self.assertRaises(ValueError):
            AbstractInterp(max_iters=0)
        with self.assertRaises(ValueError):
            AbstractInterp(narrow_steps=True)


class TestAuditEvents(unittest.TestCase):
    def test_shapes(self):
        e = abstract_interp_audit_event("analysis-finished", 3, detail="ok")
        self.assertEqual(e["schema"], "audit.ndjson/1")
        self.assertEqual(e["kind"], "abstract-interp.analysis-finished")
        self.assertEqual(e["module"], ABSTRACT_INTERP_SCHEMA)
        self.assertEqual(e["seq"], 3)
        self.assertEqual(e["detail"], "ok")

    def test_rejections(self):
        with self.assertRaises(ValueError):
            abstract_interp_audit_event("nope", 0)
        with self.assertRaises(ValueError):
            abstract_interp_audit_event("widened", -1)
        with self.assertRaises(TypeError):
            abstract_interp_audit_event("widened", 0, detail=123)


if __name__ == "__main__":
    unittest.main()
