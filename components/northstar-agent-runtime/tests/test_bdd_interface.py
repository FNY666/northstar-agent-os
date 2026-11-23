"""Tests for bdd_interface.py — reduced ordered BDDs (Bryant 1986)."""

import unittest

from bdd_interface import (
    BDDError,
    BDD,
    BDDRef,
    BDD_VERSION,
    SCHEMA_PIN,
    bdd_audit_event,
    main,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(BDD_VERSION, "bdd-interface.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.bdd-interface.v1")


class TestVariables(unittest.TestCase):
    def test_var_returns_ref(self):
        bdd = BDD()
        x = bdd.var("x")
        self.assertIsInstance(x, BDDRef)

    def test_var_reuse_same_name(self):
        bdd = BDD()
        x1 = bdd.var("x")
        x2 = bdd.var("x")
        self.assertTrue(bdd.equivalent(x1, x2))
        self.assertEqual(bdd.var_count(), 1)

    def test_var_ordering(self):
        bdd = BDD()
        bdd.var("b")
        bdd.var("a")
        self.assertEqual(bdd.var_names(), ("b", "a"))

    def test_bad_names_rejected(self):
        bdd = BDD()
        for bad in ("", True, False, 1, None, b"x", ["x"]):
            with self.assertRaises((TypeError, ValueError), msg=repr(bad)):
                bdd.var(bad)


class TestOps(unittest.TestCase):
    def test_and(self):
        bdd = BDD()
        x, y = bdd.var("x"), bdd.var("y")
        f = bdd.and_op(x, y)
        self.assertTrue(bdd.evaluate(f, {"x": True, "y": True}))
        self.assertFalse(bdd.evaluate(f, {"x": True, "y": False}))

    def test_or(self):
        bdd = BDD()
        x, y = bdd.var("x"), bdd.var("y")
        f = bdd.or_op(x, y)
        self.assertTrue(bdd.evaluate(f, {"x": False, "y": True}))
        self.assertFalse(bdd.evaluate(f, {"x": False, "y": False}))

    def test_not(self):
        bdd = BDD()
        x = bdd.var("x")
        nx = bdd.not_op(x)
        self.assertTrue(bdd.evaluate(nx, {"x": False}))
        self.assertFalse(bdd.evaluate(nx, {"x": True}))
        self.assertTrue(bdd.equivalent(x, bdd.not_op(nx)))  # double negation

    def test_xor(self):
        bdd = BDD()
        x, y = bdd.var("x"), bdd.var("y")
        f = bdd.xor_op(x, y)
        self.assertEqual(bdd.sat_count(f), 2)
        self.assertTrue(bdd.evaluate(f, {"x": True, "y": False}))

    def test_implies(self):
        bdd = BDD()
        x, y = bdd.var("x"), bdd.var("y")
        f = bdd.implies_op(x, y)
        self.assertFalse(bdd.evaluate(f, {"x": True, "y": False}))
        self.assertTrue(bdd.evaluate(f, {"x": False, "y": False}))

    def test_canonical_equivalence(self):
        bdd = BDD()
        x, y = bdd.var("x"), bdd.var("y")
        # (x & y) built two ways -> same node identity
        self.assertTrue(bdd.equivalent(bdd.and_op(x, y), bdd.and_op(y, x)))
        # idempotence
        self.assertTrue(bdd.equivalent(bdd.and_op(x, x), x))
        self.assertTrue(bdd.equivalent(bdd.or_op(x, x), x))

    def test_foreign_nodes_rejected(self):
        bdd1, bdd2 = BDD(), BDD()
        x = bdd1.var("x")
        y = bdd2.var("y")
        with self.assertRaises(BDDError):
            bdd1.and_op(x, y)
        with self.assertRaises(BDDError):
            bdd2.not_op(x)

    def test_non_ref_rejected(self):
        bdd = BDD()
        x = bdd.var("x")
        for bad in (None, 0, 1, "x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                bdd.and_op(x, bad)


class TestSatCount(unittest.TestCase):
    def test_and_count(self):
        bdd = BDD()
        x, y = bdd.var("x"), bdd.var("y")
        self.assertEqual(bdd.sat_count(bdd.and_op(x, y)), 1)

    def test_or_count(self):
        bdd = BDD()
        x, y = bdd.var("x"), bdd.var("y")
        self.assertEqual(bdd.sat_count(bdd.or_op(x, y)), 3)

    def test_tautology_counts_all(self):
        bdd = BDD()
        x = bdd.var("x")
        bdd.var("y")
        bdd.var("z")
        self.assertEqual(bdd.sat_count(bdd.or_op(x, bdd.not_op(x))), 8)

    def test_contradiction_counts_zero(self):
        bdd = BDD()
        x = bdd.var("x")
        bdd.var("y")
        self.assertEqual(bdd.sat_count(bdd.and_op(x, bdd.not_op(x))), 0)

    def test_skipped_vars_double(self):
        bdd = BDD()
        x = bdd.var("x")  # y declared but unused in f
        bdd.var("y")
        self.assertEqual(bdd.sat_count(x), 2)
        self.assertEqual(bdd.sat_count(bdd.not_op(x)), 2)

    def test_single_var_no_skip(self):
        bdd = BDD()
        x = bdd.var("x")
        self.assertEqual(bdd.sat_count(x), 1)

    def test_brute_force_agreement(self):
        # (x | y) & (y -> z): brute force over 8 assignments = ?
        bdd = BDD()
        x, y, z = bdd.var("x"), bdd.var("y"), bdd.var("z")
        f = bdd.and_op(bdd.or_op(x, y), bdd.implies_op(y, z))
        brute = 0
        for bx in (False, True):
            for by in (False, True):
                for bz in (False, True):
                    a = {"x": bx, "y": by, "z": bz}
                    if bdd.evaluate(f, a):
                        brute += 1
        self.assertEqual(bdd.sat_count(f), brute)
        self.assertEqual(brute, 4)  # pinned truth value


class TestViews(unittest.TestCase):
    def test_is_true_false(self):
        bdd = BDD()
        x = bdd.var("x")
        self.assertTrue(bdd.is_true(bdd.or_op(x, bdd.not_op(x))))
        self.assertTrue(bdd.is_false(bdd.and_op(x, bdd.not_op(x))))
        self.assertFalse(bdd.is_true(x))
        self.assertFalse(bdd.is_false(x))

    def test_node_count_shared(self):
        bdd = BDD()
        x, y = bdd.var("x"), bdd.var("y")
        g = bdd.or_op(x, y)
        # terminals 0,1 + x-node + y-node = 4
        self.assertEqual(bdd.node_count(g), 4)

    def test_node_info(self):
        bdd = BDD()
        x = bdd.var("x")
        info = bdd.node_info(x)
        self.assertEqual(info.var, "x")
        self.assertEqual(info.var_index, 0)
        self.assertFalse(info.is_terminal)
        self.assertEqual(info.as_dict()["schema"], SCHEMA_PIN)

    def test_node_info_terminal(self):
        bdd = BDD()
        x = bdd.var("x")
        info = bdd.node_info(bdd.or_op(x, bdd.not_op(x)))
        self.assertTrue(info.is_terminal)
        self.assertIsNone(info.var)


class TestEvaluate(unittest.TestCase):
    def test_missing_var_rejected(self):
        bdd = BDD()
        x = bdd.var("x")
        with self.assertRaises(BDDError):
            bdd.evaluate(x, {})

    def test_non_bool_value_rejected(self):
        bdd = BDD()
        x = bdd.var("x")
        with self.assertRaises(TypeError):
            bdd.evaluate(x, {"x": 1})

    def test_non_dict_assignment_rejected(self):
        bdd = BDD()
        x = bdd.var("x")
        with self.assertRaises(TypeError):
            bdd.evaluate(x, [("x", True)])

    def test_all_sat(self):
        bdd = BDD()
        x, y = bdd.var("x"), bdd.var("y")
        sols = bdd.all_sat(bdd.xor_op(x, y))
        self.assertEqual(len(sols), 2)
        self.assertIn({"x": True, "y": False}, sols)
        self.assertIn({"x": False, "y": True}, sols)

    def test_all_sat_limit(self):
        bdd = BDD()
        bdd.var("x")
        bdd.var("y")
        x = bdd.var("x")
        # x is true in 2 of 4 assignments, but limit=1
        sols = bdd.all_sat(x, limit=1)
        self.assertEqual(len(sols), 1)
        with self.assertRaises(ValueError):
            bdd.all_sat(x, limit=0)


class TestAudit(unittest.TestCase):
    def test_audit_event_shape(self):
        bdd = BDD()
        x, y = bdd.var("x"), bdd.var("y")
        ev = bdd_audit_event(bdd, bdd.and_op(x, y), "built", 3)
        self.assertEqual(ev["event"], "bdd-interface")
        self.assertEqual(ev["outcome"], "built")
        self.assertEqual(ev["audit_seq"], 3)
        self.assertEqual(ev["schema"], "audit.ndjson/1")

    def test_audit_bad_outcome(self):
        bdd = BDD()
        x = bdd.var("x")
        with self.assertRaises(ValueError):
            bdd_audit_event(bdd, x, "exploded", 0)

    def test_audit_bad_seq(self):
        bdd = BDD()
        x = bdd.var("x")
        for bad in (-1, True, "0"):
            with self.assertRaises((TypeError, ValueError), msg=repr(bad)):
                bdd_audit_event(bdd, x, "built", bad)


class TestMain(unittest.TestCase):
    def test_main(self):
        main()


if __name__ == "__main__":
    unittest.main()
