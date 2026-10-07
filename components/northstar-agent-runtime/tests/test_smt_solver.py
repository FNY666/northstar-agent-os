"""Tests for smt_solver.py (SMT assert/check-sat interface, finite-domain)."""

import ast
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from smt_solver import (
    TRUE,
    FALSE,
    Add,
    And,
    BoolConst,
    BoolVar,
    Eq,
    Ge,
    Gt,
    Implies,
    IntConst,
    IntVar,
    Ite,
    Le,
    Lt,
    Model,
    Mul,
    Ne,
    Neg,
    Not,
    Or,
    SatResult,
    SMTError,
    SMTSolver,
    Sub,
    SMT_SOLVER_SCHEMA,
    SMT_SOLVER_VERSION,
    smt_solver_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(SMT_SOLVER_VERSION, "smt-solver.v1")

    def test_schema_pin(self):
        self.assertEqual(SMT_SOLVER_SCHEMA, "northstar.smt-solver.v1")


class TestConstruction(unittest.TestCase):
    def test_int_var_bounds(self):
        v = IntVar("x", 0, 5)
        self.assertTrue(v.bounded)
        self.assertEqual((v.lo, v.hi), (0, 5))

    def test_int_var_unbounded(self):
        v = IntVar("z")
        self.assertFalse(v.bounded)

    def test_var_bad_name(self):
        for bad in ("", 1, True, None, b"x"):
            with self.assertRaises(SMTError):
                IntVar(bad, 0, 1)
            with self.assertRaises(SMTError):
                BoolVar(bad)

    def test_int_var_bad_bounds(self):
        with self.assertRaises(SMTError):
            IntVar("x", 5, 0)  # lo > hi
        with self.assertRaises(SMTError):
            IntVar("x", 0, None)  # half-bounded
        with self.assertRaises(SMTError):
            IntVar("x", None, 5)  # half-bounded
        with self.assertRaises(SMTError):
            IntVar("x", True, 5)  # bool bound
        with self.assertRaises(SMTError):
            IntVar("x", 0.5, 5)  # float bound

    def test_const_validation(self):
        with self.assertRaises(SMTError):
            IntConst(True)  # bool is not an int here
        with self.assertRaises(SMTError):
            IntConst(1.5)
        with self.assertRaises(SMTError):
            BoolConst(1)
        with self.assertRaises(SMTError):
            BoolConst("true")

    def test_sort_checking(self):
        x = IntVar("x", 0, 2)
        b = BoolVar("b")
        with self.assertRaises(SMTError):
            Add((x, b))
        with self.assertRaises(SMTError):
            Eq(x, b)
        with self.assertRaises(SMTError):
            And((x,))
        with self.assertRaises(SMTError):
            Not(x)
        with self.assertRaises(SMTError):
            Ite(x, IntConst(1), IntConst(2))  # non-bool cond
        with self.assertRaises(SMTError):
            Ite(b, IntConst(1), TRUE)  # branch sort mismatch
        with self.assertRaises(SMTError):
            Add((x,))  # too few args
        with self.assertRaises(SMTError):
            Sub(x, b)

    def test_true_false_consts(self):
        self.assertEqual(TRUE.value, True)
        self.assertEqual(FALSE.value, False)


class TestAssert(unittest.TestCase):
    def test_assert_returns_index(self):
        s = SMTSolver()
        x = IntVar("x", 0, 2)
        self.assertEqual(s.assert_expr(Eq(x, IntConst(1))), 0)
        self.assertEqual(s.assert_expr(Ge(x, IntConst(0))), 1)

    def test_assert_non_bool_rejected(self):
        s = SMTSolver()
        x = IntVar("x", 0, 2)
        with self.assertRaises(SMTError):
            s.assert_expr(x)
        with self.assertRaises(SMTError):
            s.assert_expr(IntConst(3))
        with self.assertRaises(SMTError):
            s.assert_expr("x == 1")

    def test_assertions_view(self):
        s = SMTSolver()
        x = IntVar("x", 0, 2)
        e = Eq(x, IntConst(1))
        s.assert_expr(e)
        self.assertEqual(s.assertions(), (e,))


class TestSat(unittest.TestCase):
    def test_simple_sat(self):
        s = SMTSolver()
        x = IntVar("x", 0, 2)
        s.assert_expr(Eq(x, IntConst(1)))
        self.assertIs(s.check_sat(), SatResult.SAT)
        self.assertEqual(s.get_model().lookup("x"), 1)

    def test_empty_assertions_sat(self):
        s = SMTSolver()
        self.assertIs(s.check_sat(), SatResult.SAT)
        self.assertEqual(s.get_model().bindings, ())

    def test_simple_unsat(self):
        s = SMTSolver()
        x = IntVar("x", 0, 1)
        s.assert_expr(Eq(x, IntConst(0)))
        s.assert_expr(Eq(x, IntConst(1)))
        self.assertIs(s.check_sat(), SatResult.UNSAT)

    def test_bool_sat(self):
        s = SMTSolver()
        a = BoolVar("a")
        b = BoolVar("b")
        s.assert_expr(Or((a, b)))
        s.assert_expr(Not(a))
        self.assertIs(s.check_sat(), SatResult.SAT)
        m = s.get_model()
        self.assertEqual(m.lookup("a"), False)
        self.assertEqual(m.lookup("b"), True)

    def test_implies_ite(self):
        s = SMTSolver()
        x = IntVar("x", 0, 5)
        b = BoolVar("b")
        s.assert_expr(Implies(b, Gt(x, IntConst(3))))
        s.assert_expr(Eq(Ite(b, IntConst(10), IntConst(0)), IntConst(10)))
        self.assertIs(s.check_sat(), SatResult.SAT)
        m = s.get_model()
        self.assertEqual(m.lookup("b"), True)
        self.assertGreater(m.lookup("x"), 3)

    def test_arithmetic(self):
        s = SMTSolver()
        x = IntVar("x", 0, 4)
        y = IntVar("y", 0, 4)
        s.assert_expr(Eq(Add((x, y)), IntConst(5)))
        s.assert_expr(Eq(Mul((x, IntConst(2))), IntConst(4)))
        self.assertIs(s.check_sat(), SatResult.SAT)
        m = s.get_model()
        self.assertEqual(m.lookup("x"), 2)
        self.assertEqual(m.lookup("y"), 3)

    def test_operator_sugar(self):
        s = SMTSolver()
        x = IntVar("x", 0, 3)
        y = IntVar("y", 0, 3)
        s.assert_expr(Eq(x + y, IntConst(3)))
        s.assert_expr(Eq(x * IntConst(2), IntConst(2)))
        s.assert_expr(Eq(-y, IntConst(-2)))
        self.assertIs(s.check_sat(), SatResult.SAT)
        m = s.get_model()
        self.assertEqual((m.lookup("x"), m.lookup("y")), (1, 2))

    def test_bool_operators(self):
        s = SMTSolver()
        a = BoolVar("a")
        b = BoolVar("b")
        s.assert_expr((a | b) & ~a)
        self.assertIs(s.check_sat(), SatResult.SAT)
        m = s.get_model()
        self.assertEqual((m.lookup("a"), m.lookup("b")), (False, True))

    def test_determinism(self):
        def build():
            s = SMTSolver()
            x = IntVar("x", 0, 9)
            y = IntVar("y", 0, 9)
            s.assert_expr(Eq(Add((x, y)), IntConst(9)))
            s.assert_expr(Lt(x, y))
            return s

        s1, s2 = build(), build()
        s1.check_sat()
        s2.check_sat()
        self.assertEqual(s1.get_model(), s2.get_model())
        self.assertEqual(s1.assertions_digest(), s2.assertions_digest())


class TestUnknown(unittest.TestCase):
    def test_unbounded_is_unknown(self):
        s = SMTSolver()
        z = IntVar("z")
        s.assert_expr(Eq(z, IntConst(1)))
        self.assertIs(s.check_sat(), SatResult.UNKNOWN)
        reason = s.last_unknown_reason()
        self.assertIsNotNone(reason)
        self.assertIn("unbounded", reason)

    def test_guardrail_is_unknown(self):
        s = SMTSolver(max_evaluations=100)
        x = IntVar("x", 0, 20)
        y = IntVar("y", 0, 20)
        s.assert_expr(Ge(x, IntConst(0)))
        s.assert_expr(Ge(y, IntConst(0)))
        self.assertIs(s.check_sat(), SatResult.UNKNOWN)
        self.assertIn("max_evaluations", s.last_unknown_reason())

    def test_var_domain_cap(self):
        s = SMTSolver(max_var_domain=10)
        x = IntVar("x", 0, 100)
        s.assert_expr(Ge(x, IntConst(0)))
        self.assertIs(s.check_sat(), SatResult.UNKNOWN)

    def test_model_after_unknown_raises(self):
        s = SMTSolver()
        s.assert_expr(Eq(IntVar("z"), IntConst(1)))
        s.check_sat()
        with self.assertRaises(SMTError):
            s.get_model()


class TestModelRules(unittest.TestCase):
    def test_model_before_check_raises(self):
        s = SMTSolver()
        with self.assertRaises(SMTError):
            s.get_model()

    def test_model_after_unsat_raises(self):
        s = SMTSolver()
        x = IntVar("x", 0, 0)
        s.assert_expr(Eq(x, IntConst(1)))
        s.check_sat()
        with self.assertRaises(SMTError):
            s.get_model()

    def test_model_invalidated_by_new_assert(self):
        s = SMTSolver()
        x = IntVar("x", 0, 2)
        s.assert_expr(Ge(x, IntConst(0)))
        s.check_sat()
        s.assert_expr(Eq(x, IntConst(2)))
        with self.assertRaises(SMTError):
            s.get_model()

    def test_model_frozen_and_sorted(self):
        with self.assertRaises(SMTError):
            Model(bindings=(("b", True), ("a", 1)))  # unsorted rejected
        with self.assertRaises(SMTError):
            Model(bindings=(("a", 1), ("a", 2)))  # duplicate rejected
        m = Model(bindings=(("a", 1), ("b", True)))
        with self.assertRaises(SMTError):
            m.lookup("nope")
        with self.assertRaises(Exception):
            m.bindings = ()  # frozen

    def test_model_as_dict(self):
        s = SMTSolver()
        x = IntVar("x", 0, 1)
        s.assert_expr(Eq(x, IntConst(1)))
        s.check_sat()
        d = s.get_model().as_dict()
        self.assertEqual(d["bindings"], {"x": 1})
        self.assertEqual(d["schema"], SMT_SOLVER_SCHEMA)


class TestUnsatCore(unittest.TestCase):
    def test_minimal_core(self):
        s = SMTSolver()
        x = IntVar("x", 0, 3)
        y = IntVar("y", 0, 3)
        s.assert_expr(Eq(Add((x, y)), IntConst(4)))  # 0
        s.assert_expr(Lt(x, y))  # 1
        s.assert_expr(Eq(x, IntConst(3)))  # 2 -> x<y impossible
        self.assertIs(s.check_sat(), SatResult.UNSAT)
        core = s.unsat_core()
        self.assertEqual(set(core), {1, 2})
        # minimality: dropping either makes it SAT
        trial = SMTSolver()
        trial.assert_expr(Lt(x, y))
        self.assertIs(trial.check_sat(), SatResult.SAT)

    def test_core_without_unsat_raises(self):
        s = SMTSolver()
        x = IntVar("x", 0, 1)
        s.assert_expr(Ge(x, IntConst(0)))
        s.check_sat()
        with self.assertRaises(SMTError):
            s.unsat_core()

    def test_core_single_assertion(self):
        s = SMTSolver()
        x = IntVar("x", 0, 0)
        s.assert_expr(Eq(x, IntConst(5)))
        s.check_sat()
        self.assertEqual(s.unsat_core(), (0,))


class TestIncremental(unittest.TestCase):
    def test_push_pop(self):
        s = SMTSolver()
        x = IntVar("x", 0, 2)
        s.assert_expr(Eq(x, IntConst(1)))
        s.push()
        s.assert_expr(Eq(x, IntConst(2)))
        self.assertIs(s.check_sat(), SatResult.UNSAT)
        s.pop()
        self.assertIs(s.check_sat(), SatResult.SAT)
        self.assertEqual(s.get_model().lookup("x"), 1)

    def test_pop_without_push_raises(self):
        s = SMTSolver()
        with self.assertRaises(SMTError):
            s.pop()

    def test_push_copies_level(self):
        s = SMTSolver()
        x = IntVar("x", 0, 2)
        s.assert_expr(Ge(x, IntConst(0)))
        s.push()
        self.assertEqual(len(s.assertions()), 1)
        s.pop()
        self.assertEqual(len(s.assertions()), 1)

    def test_reset(self):
        s = SMTSolver()
        x = IntVar("x", 0, 1)
        s.assert_expr(Eq(x, IntConst(0)))
        s.check_sat()
        s.reset()
        self.assertEqual(s.assertions(), ())
        self.assertEqual(s.stats()["checks"], 0)
        self.assertIs(s.check_sat(), SatResult.SAT)


class TestDigestStats(unittest.TestCase):
    def test_digest_changes_with_assertions(self):
        s = SMTSolver()
        d0 = s.assertions_digest()
        x = IntVar("x", 0, 1)
        s.assert_expr(Eq(x, IntConst(0)))
        d1 = s.assertions_digest()
        self.assertNotEqual(d0, d1)
        self.assertTrue(d1.startswith("sha256:"))

    def test_stats(self):
        s = SMTSolver()
        x = IntVar("x", 0, 1)
        s.assert_expr(Eq(x, IntConst(0)))
        s.check_sat()
        st = s.stats()
        self.assertEqual(st["assertions"], 1)
        self.assertEqual(st["checks"], 1)
        self.assertGreaterEqual(st["evaluations_total"], 1)
        self.assertEqual(st["stack_depth"], 1)


class TestAudit(unittest.TestCase):
    def _solver(self):
        s = SMTSolver()
        x = IntVar("x", 0, 1)
        s.assert_expr(Eq(x, IntConst(1)))
        return s

    def test_asserted_event(self):
        ev = smt_solver_audit_event("asserted", self._solver(), 7)
        self.assertEqual(ev["kind"], "asserted")
        self.assertEqual(ev["seq"], 7)
        self.assertEqual(ev["assertions"], 1)
        self.assertTrue(ev["assertions_digest"].startswith("sha256:"))
        self.assertEqual(ev["schema"], SMT_SOLVER_SCHEMA)

    def test_checked_event(self):
        s = self._solver()
        r = s.check_sat()
        ev = smt_solver_audit_event("checked", s, 3, result=r)
        self.assertEqual(ev["result"], "sat")

    def test_checked_unknown_carries_reason(self):
        s = SMTSolver()
        s.assert_expr(Eq(IntVar("z"), IntConst(1)))
        r = s.check_sat()
        ev = smt_solver_audit_event("checked", s, 1, result=r)
        self.assertEqual(ev["result"], "unknown")
        self.assertIn("unbounded", ev["unknown_reason"])

    def test_other_kinds(self):
        s = self._solver()
        for kind in ("pushed", "popped", "reset"):
            ev = smt_solver_audit_event(kind, s, 0)
            self.assertEqual(ev["kind"], kind)

    def test_audit_rejections(self):
        s = self._solver()
        with self.assertRaises(SMTError):
            smt_solver_audit_event("bogus", s, 0)
        with self.assertRaises(SMTError):
            smt_solver_audit_event("asserted", s, -1)
        with self.assertRaises(SMTError):
            smt_solver_audit_event("asserted", s, True)
        with self.assertRaises(SMTError):
            smt_solver_audit_event("asserted", "not-a-solver", 0)
        with self.assertRaises(SMTError):
            smt_solver_audit_event("checked", s, 0)  # missing result
        with self.assertRaises(SMTError):
            smt_solver_audit_event("asserted", s, 0, result=SatResult.SAT)


class TestHouseStyle(unittest.TestCase):
    def test_stdlib_only(self):
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "smt_solver.py",
        )
        tree = ast.parse(open(path).read())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        allowed = {"__future__", "dataclasses", "enum", "hashlib", "typing"}
        self.assertLessEqual(imported, allowed, imported - allowed)

    def test_main_runs(self):
        import smt_solver

        smt_solver.main()  # prints self-check line; raises on failure


if __name__ == "__main__":
    unittest.main()
