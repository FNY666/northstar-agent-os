"""Tests for sat_solver (DPLL)."""

import ast
import sys
import unittest

sys.path.insert(0, "..")

from sat_solver import (
    SAT_SOLVER_VERSION,
    SCHEMA_PIN,
    EmptyClauseError,
    SATError,
    SATSolver,
    SolverResult,
    sat_solver_audit_event,
    verify_assignment,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(SAT_SOLVER_VERSION, "sat-solver.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.sat-solver.v1")


class TestClauseValidation(unittest.TestCase):
    def test_add_single_literal(self):
        s = SATSolver()
        s.add_clause(1)
        self.assertEqual(s.n_clauses, 1)
        self.assertEqual(s.n_vars, 1)

    def test_literal_zero_rejected(self):
        with self.assertRaises(SATError):
            SATSolver().add_clause(0)

    def test_bool_literal_rejected(self):
        with self.assertRaises(SATError):
            SATSolver().add_clause(True)

    def test_str_literal_rejected(self):
        with self.assertRaises(SATError):
            SATSolver().add_clause("1")

    def test_float_literal_rejected(self):
        with self.assertRaises(SATError):
            SATSolver().add_clause(1.5)

    def test_empty_clause_raises_and_poisons(self):
        s = SATSolver()
        with self.assertRaises(EmptyClauseError):
            s.add_clause()
        r = s.solve()
        self.assertEqual(r.verdict, "unsat")

    def test_tautology_dropped(self):
        s = SATSolver()
        s.add_clause(1, -1, 2)
        self.assertEqual(s.n_clauses, 0)  # dropped, always satisfied
        r = s.solve()
        self.assertEqual(r.verdict, "sat")

    def test_duplicate_literals_collapse(self):
        s = SATSolver()
        s.add_clause(1, 1, 2, 2)
        self.assertEqual(s.n_clauses, 1)
        r = s.solve()
        self.assertEqual(r.verdict, "sat")


class TestSolveBasic(unittest.TestCase):
    def test_single_unit_sat(self):
        s = SATSolver()
        s.add_clause(5)
        r = s.solve()
        self.assertEqual(r.verdict, "sat")
        self.assertEqual(r.model(), {5: True})

    def test_direct_contradiction_unsat(self):
        s = SATSolver()
        s.add_clauses([(1,), (-1,)])
        r = s.solve()
        self.assertEqual(r.verdict, "unsat")

    def test_empty_formula_sat(self):
        r = SATSolver().solve()
        self.assertEqual(r.verdict, "sat")
        # assignment covers no variables; vacuous truth
        self.assertTrue(verify_assignment(r.assignment, []))

    def test_three_clause_sat(self):
        clauses = [(1, 2), (-1, 2), (1, -2)]
        s = SATSolver()
        s.add_clauses(clauses)
        r = s.solve()
        self.assertEqual(r.verdict, "sat")
        self.assertTrue(verify_assignment(r.assignment, clauses))

    def test_four_clause_unsat(self):
        s = SATSolver()
        s.add_clauses([(1, 2), (-1, 2), (1, -2), (-1, -2)])
        r = s.solve()
        self.assertEqual(r.verdict, "unsat")

    def test_unit_propagation_chain(self):
        # 1, -1|2, -2|3 forces 3=True
        s = SATSolver()
        s.add_clauses([(1,), (-1, 2), (-2, 3)])
        r = s.solve()
        self.assertEqual(r.verdict, "sat")
        self.assertEqual(r.model()[3], True)
        self.assertGreaterEqual(r.propagations, 2)

    def test_unit_conflict_unsat(self):
        # 1, -1|2, -2 -> conflict at unit propagation depth
        s = SATSolver()
        s.add_clauses([(1,), (-1, 2), (-2,)])
        r = s.solve()
        self.assertEqual(r.verdict, "unsat")

    def test_pure_literal(self):
        # 3 appears only positively; solver may set 3=True
        s = SATSolver()
        s.add_clauses([(1, 3), (2, 3), (-1, 2)])
        r = s.solve()
        self.assertEqual(r.verdict, "sat")
        self.assertTrue(verify_assignment(r.assignment, [(1, 3), (2, 3), (-1, 2)]))

    def test_3sat_sat_instance(self):
        clauses = [
            (1, -2, 3), (-1, 2, 4), (2, -3, -4),
            (-2, 3, 1), (4, -1, -3), (-4, -2, 3),
        ]
        s = SATSolver()
        s.add_clauses(clauses)
        r = s.solve()
        self.assertEqual(r.verdict, "sat")
        self.assertTrue(verify_assignment(r.assignment, clauses))

    def test_planted_assignment_satisfiable(self):
        # Plant solution x1=T, x2=F, x3=T, x4=T; every clause hits it.
        clauses = [
            (1, 2, -3), (-1, 2, 4), (3, -4, 1),
            (-2, -4, 3), (1, 3, 4), (-2, 1, -4),
        ]
        s = SATSolver()
        s.add_clauses(clauses)
        r = s.solve()
        self.assertEqual(r.verdict, "sat")
        self.assertTrue(verify_assignment(r.assignment, clauses))


class TestDeterminism(unittest.TestCase):
    def test_same_model_twice(self):
        def run():
            s = SATSolver()
            s.add_clauses([(1, 2, 3), (-1, -2), (2, -3), (-1, 3, -2)])
            return s.solve().assignment

        self.assertEqual(run(), run())

    def test_unsat_stable(self):
        def run():
            s = SATSolver()
            s.add_clauses([(1, 2), (-1, 2), (1, -2), (-1, -2)])
            return s.solve().verdict

        self.assertEqual(run(), run())


class TestAssumptions(unittest.TestCase):
    def test_assumption_satisfiable(self):
        s = SATSolver()
        s.add_clauses([(1, 2), (-1, -2)])
        r = s.solve(assumptions=(1,))
        self.assertEqual(r.verdict, "sat")
        self.assertEqual(r.model()[1], True)

    def test_assumption_unsatisfiable(self):
        s = SATSolver()
        s.add_clauses([(1,), (-1,)])
        r = s.solve(assumptions=(1,))
        self.assertEqual(r.verdict, "unsat")

    def test_conflicting_assumptions_unsat(self):
        s = SATSolver()
        s.add_clause(1, 2)
        r = s.solve(assumptions=(1, -1))
        self.assertEqual(r.verdict, "unsat")

    def test_assumption_does_not_pollute(self):
        s = SATSolver()
        s.add_clause(1)
        r1 = s.solve(assumptions=(-1,))  # conflicts with stored unit
        self.assertEqual(r1.verdict, "unsat")
        r2 = s.solve()  # stored formula alone is fine
        self.assertEqual(r2.verdict, "sat")

    def test_bad_assumption_rejected(self):
        with self.assertRaises(SATError):
            SATSolver().solve(assumptions=(0,))


class TestBudget(unittest.TestCase):
    def test_zero_budget_unknown(self):
        s = SATSolver()
        s.add_clauses([(1, 2), (-1, 2), (1, -2), (-1, -2)])
        r = s.solve(max_decisions=0)
        self.assertEqual(r.verdict, "unknown")

    def test_generous_budget_solves(self):
        s = SATSolver()
        s.add_clauses([(1, 2), (-1, 2), (1, -2), (-1, -2)])
        r = s.solve(max_decisions=1000)
        self.assertEqual(r.verdict, "unsat")

    def test_negative_budget_rejected(self):
        with self.assertRaises(SATError):
            SATSolver().solve(max_decisions=-1)

    def test_bool_budget_rejected(self):
        with self.assertRaises(SATError):
            SATSolver().solve(max_decisions=True)

    def test_huge_budget_rejected(self):
        with self.assertRaises(SATError):
            SATSolver().solve(max_decisions=10**10)


class TestResultRecord(unittest.TestCase):
    def test_stats(self):
        s = SATSolver()
        s.add_clauses([(1, 2), (-1, 3)])
        r = s.solve()
        self.assertEqual(r.verdict, "sat")
        self.assertEqual(r.n_vars, 3)
        self.assertEqual(r.n_clauses, 2)

    def test_branching_counted(self):
        s = SATSolver()
        # Forces at least one branching decision.
        s.add_clauses([(1, 2), (-1, -2)])
        r = s.solve()
        self.assertEqual(r.verdict, "sat")
        self.assertGreaterEqual(r.decisions, 1)

    def test_as_dict_shape(self):
        s = SATSolver()
        s.add_clause(1)
        r = s.solve()
        d = r.as_dict()
        self.assertEqual(d["verdict"], "sat")
        self.assertEqual(d["assignment"], [1])
        self.assertEqual(d["version"], "sat-solver.v1")
        self.assertEqual(d["schema"], "northstar.sat-solver.v1")

    def test_bad_verdict_rejected(self):
        with self.assertRaises(SATError):
            SolverResult(verdict="maybe")

    def test_unsat_with_assignment_rejected(self):
        with self.assertRaises(SATError):
            SolverResult(verdict="unsat", assignment=(1,))

    def test_inconsistent_assignment_rejected(self):
        with self.assertRaises(SATError):
            SolverResult(verdict="sat", assignment=(1, -1))

    def test_model_none_when_unsat(self):
        s = SATSolver()
        s.add_clauses([(1,), (-1,)])
        self.assertIsNone(s.solve().model())


class TestVerifyAssignment(unittest.TestCase):
    def test_verify_good(self):
        self.assertTrue(verify_assignment([1, -2], [(1, 2), (-2, 3)]))

    def test_verify_bad(self):
        self.assertFalse(verify_assignment([-1, 2], [(1, 2), (-2,)]))

    def test_verify_empty(self):
        self.assertTrue(verify_assignment([], []))

    def test_verify_bad_type(self):
        with self.assertRaises(SATError):
            verify_assignment("1", [(1,)])


class TestAuditEvents(unittest.TestCase):
    def _sat_result(self):
        s = SATSolver()
        s.add_clause(1)
        return s.solve()

    def _unsat_result(self):
        s = SATSolver()
        s.add_clauses([(1,), (-1,)])
        return s.solve()

    def test_solved_sat_shape(self):
        ev = sat_solver_audit_event("solved-sat", self._sat_result(), 3)
        self.assertEqual(ev["event"], "sat-solver")
        self.assertEqual(ev["audit_seq"], 3)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["result"]["verdict"], "sat")

    def test_solved_unsat_shape(self):
        ev = sat_solver_audit_event("solved-unsat", self._unsat_result(), 0)
        self.assertEqual(ev["kind"], "solved-unsat")
        self.assertEqual(ev["result"]["verdict"], "unsat")

    def test_unknown_shape(self):
        s = SATSolver()
        s.add_clauses([(1, 2), (-1, 2), (1, -2), (-1, -2)])
        r = s.solve(max_decisions=0)
        ev = sat_solver_audit_event("solve-unknown", r, 1)
        self.assertEqual(ev["result"]["verdict"], "unknown")

    def test_clause_added_shape(self):
        ev = sat_solver_audit_event("clause-added", None, 7)
        self.assertEqual(ev["kind"], "clause-added")
        self.assertNotIn("result", ev)

    def test_bad_kind_rejected(self):
        with self.assertRaises(ValueError):
            sat_solver_audit_event("nope", None, 0)

    def test_bad_seq_rejected(self):
        with self.assertRaises(ValueError):
            sat_solver_audit_event("clause-added", None, -1)
        with self.assertRaises(ValueError):
            sat_solver_audit_event("clause-added", None, True)

    def test_kind_result_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            sat_solver_audit_event("solved-unsat", self._sat_result(), 0)

    def test_result_type_rejected(self):
        with self.assertRaises(TypeError):
            sat_solver_audit_event("solved-sat", None, 0)

    def test_clause_added_with_result_rejected(self):
        with self.assertRaises(TypeError):
            sat_solver_audit_event("clause-added", self._sat_result(), 0)


class TestStdlibOnly(unittest.TestCase):
    def test_imports(self):
        import sat_solver

        tree = ast.parse(open(sat_solver.__file__).read())
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add(node.module.split(".")[0])
        self.assertLessEqual(imports, {"dataclasses", "typing", "__future__"})


if __name__ == "__main__":
    unittest.main()
