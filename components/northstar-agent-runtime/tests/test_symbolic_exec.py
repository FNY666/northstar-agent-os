"""Tests for the symbolic execution interface (simulated)."""

import unittest

from symbolic_exec import (
    SCHEMA_PIN,
    SYMBOLIC_EXEC_VERSION,
    ExecutionReport,
    PathResult,
    Solution,
    SymbolicExec,
    SymbolicExecError,
    solve,
    symbolic_exec_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(SYMBOLIC_EXEC_VERSION, "symbolic-exec.v1")
        self.assertEqual(SymbolicExec().version, "symbolic-exec.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.symbolic-exec.v1")


class TestExecute(unittest.TestCase):
    def test_linear_program(self):
        ex = SymbolicExec()
        report = ex.execute(
            [("sym", "x"), ("const", "y", 7), ("halt", "y")]
        )
        self.assertIsInstance(report, ExecutionReport)
        self.assertEqual(len(report.paths), 1)
        self.assertEqual(report.forks, 0)
        self.assertEqual(report.pruned, 0)
        self.assertTrue(report.digest.startswith("sha256:"))

    def test_branch_forks_two_paths(self):
        ex = SymbolicExec()
        report = ex.execute(
            [("sym", "x"), ("branch", "lt", "x", 10), ("halt",)]
        )
        self.assertEqual(report.forks, 1)
        self.assertEqual(len(report.paths), 2)
        self.assertEqual(report.pruned, 0)
        self.assertEqual(report.paths[0].path_id, "p0")
        self.assertEqual(report.paths[1].path_id, "p1")

    def test_branch_constraint_shapes(self):
        ex = SymbolicExec()
        report = ex.execute(
            [("sym", "x"), ("branch", "lt", "x", 10), ("halt",)]
        )
        ops = [p.constraints[0][0] for p in report.paths]
        self.assertEqual(sorted(ops), ["ge", "lt"])

    def test_impossible_branch_side_pruned(self):
        ex = SymbolicExec()
        report = ex.execute(
            [
                ("sym", "x"),
                ("assume", "lt", "x", 0),
                ("assume", "gt", "x", 5),
                ("halt",),
            ]
        )
        # second assume contradicts the first: path dies
        self.assertEqual(len(report.paths), 0)
        self.assertEqual(report.pruned, 1)

    def test_arithmetic_expression(self):
        ex = SymbolicExec()
        report = ex.execute(
            [
                ("sym", "x"),
                ("const", "c", 3),
                ("add", "z", "x", "c"),
                ("halt", "z"),
            ]
        )
        self.assertEqual(len(report.paths), 1)
        path = report.paths[0]
        self.assertEqual(path.output, ("+", ("var", "x"), ("lit", 3)))

    def test_state_digest_deterministic(self):
        ex = SymbolicExec()
        r1 = ex.execute([("sym", "x"), ("halt",)])
        r2 = ex.execute([("sym", "x"), ("halt",)])
        self.assertEqual(r1.digest, r2.digest)

    def test_report_as_dict(self):
        ex = SymbolicExec()
        report = ex.execute([("sym", "x"), ("halt",)])
        d = report.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(len(d["paths"]), 1)
        self.assertIn("state_digest", d["paths"][0])

    def test_unknown_instruction_rejected(self):
        ex = SymbolicExec()
        with self.assertRaises(SymbolicExecError):
            ex.execute([("jump", "x")])

    def test_non_list_program_rejected(self):
        ex = SymbolicExec()
        with self.assertRaises(TypeError):
            ex.execute("not a program")

    def test_undeclared_variable_rejected(self):
        ex = SymbolicExec()
        with self.assertRaises(SymbolicExecError):
            ex.execute([("add", "z", "ghost", 1), ("halt",)])

    def test_fell_off_end_rejected(self):
        ex = SymbolicExec()
        with self.assertRaises(SymbolicExecError):
            ex.execute([("sym", "x")])

    def test_redeclare_rejected(self):
        ex = SymbolicExec()
        with self.assertRaises(SymbolicExecError):
            ex.execute([("sym", "x"), ("sym", "x"), ("halt",)])

    def test_bool_variable_rejected(self):
        ex = SymbolicExec()
        with self.assertRaises(TypeError):
            ex.execute([("sym", True), ("halt",)])


class TestSolve(unittest.TestCase):
    def test_sat_equality(self):
        sol = solve((("eq", "x", 5),))
        self.assertIsInstance(sol, Solution)
        self.assertTrue(sol.sat)
        self.assertEqual(sol.assignment, {"x": 5})

    def test_sat_range(self):
        sol = solve((("ge", "x", 3), ("le", "x", 7)))
        self.assertTrue(sol.sat)
        self.assertTrue(3 <= sol.assignment["x"] <= 7)

    def test_unsat_contradiction(self):
        sol = solve((("lt", "x", 0), ("gt", "x", 10)))
        self.assertFalse(sol.sat)
        self.assertIsNone(sol.assignment)

    def test_unsat_empty_interval(self):
        sol = solve((("eq", "x", 1), ("eq", "x", 2)))
        self.assertFalse(sol.sat)

    def test_ne_constraint(self):
        sol = solve((("ne", "x", 5), ("eq", "x", 5)))
        self.assertFalse(sol.sat)

    def test_empty_constraints_sat(self):
        sol = solve(())
        self.assertTrue(sol.sat)
        self.assertEqual(sol.assignment, {})

    def test_multi_variable(self):
        sol = solve((("eq", "a", 1), ("eq", "b", 2)))
        self.assertTrue(sol.sat)
        self.assertEqual(sol.assignment, {"a": 1, "b": 2})

    def test_expression_constraint(self):
        sol = solve((("eq", ("+", "x", 1), 6),))
        self.assertTrue(sol.sat)
        self.assertEqual(sol.assignment["x"], 5)

    def test_bad_shape_rejected(self):
        with self.assertRaises(SymbolicExecError):
            solve((("bogus", "x", 1),))

    def test_solution_as_dict(self):
        sol = solve((("eq", "x", 5),))
        d = sol.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertTrue(d["sat"])

    def test_unsat_as_dict(self):
        d = solve((("lt", "x", 0), ("gt", "x", 10))).as_dict()
        self.assertFalse(d["sat"])
        self.assertIsNone(d["assignment"])


class TestAuditEvents(unittest.TestCase):
    def test_event_shape(self):
        ev = symbolic_exec_audit_event("executed", 3, paths=2)
        self.assertEqual(ev["event"], "symbolic-exec")
        self.assertEqual(ev["kind"], "executed")
        self.assertEqual(ev["audit_seq"], 3)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["paths"], 2)

    def test_all_kinds(self):
        for kind in ("executed", "path-forked", "path-pruned", "solved", "unsat"):
            ev = symbolic_exec_audit_event(kind, 0)
            self.assertEqual(ev["kind"], kind)

    def test_bad_kind_rejected(self):
        with self.assertRaises(ValueError):
            symbolic_exec_audit_event("nope", 0)

    def test_bad_seq_rejected(self):
        with self.assertRaises(ValueError):
            symbolic_exec_audit_event("solved", -1)
        with self.assertRaises(ValueError):
            symbolic_exec_audit_event("solved", True)


class TestRecords(unittest.TestCase):
    def test_path_result_frozen(self):
        ex = SymbolicExec()
        report = ex.execute([("sym", "x"), ("halt",)])
        path = report.paths[0]
        self.assertIsInstance(path, PathResult)
        with self.assertRaises(Exception):
            path.path_id = "q"  # frozen dataclass

    def test_solution_frozen(self):
        sol = solve((("eq", "x", 1),))
        with self.assertRaises(Exception):
            sol.sat = False  # frozen dataclass

    def test_main_self_check(self):
        from symbolic_exec import main

        main()  # asserts internally; raises on failure


if __name__ == "__main__":
    unittest.main()
