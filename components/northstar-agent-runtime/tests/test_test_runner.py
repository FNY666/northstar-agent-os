"""Tests for test_runner."""

import ast
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import test_runner as tr


class TestPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(tr.TEST_RUNNER_VERSION, "test-runner.v1")
        self.assertEqual(tr.SCHEMA_PIN, "northstar.test-runner.v1")
        self.assertEqual(tr.AUDIT_SCHEMA, "audit.ndjson/1")

    def test_stdlib_only(self):
        tree = ast.parse(open(tr.__file__).read())
        allowed = {"__future__", "re", "threading", "dataclasses", "typing",
                   "hashlib", "json", "canonical_json"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertTrue(a.name.split(".")[0] in allowed,
                                    f"non-stdlib import: {a.name}")
            elif isinstance(node, ast.ImportFrom):
                self.assertTrue((node.module or "").split(".")[0] in allowed,
                                f"non-stdlib import: {node.module}")


def make_runner():
    r = tr.TestRunner()
    r.register_test("t1", "unit", 1, labels=["fast"], timeout_ms=1000)
    r.register_test("t2", "unit", 2, labels=["slow"])
    r.register_test("t3", "integration", 3)
    return r


class TestRegister(unittest.TestCase):
    def test_roundtrip(self):
        r = tr.TestRunner()
        rec = r.register_test("abc", "suite-x", 1)
        self.assertEqual(rec.test_id, "abc")
        self.assertEqual(r.test_record("abc").suite, "suite-x")

    def test_duplicate(self):
        r = make_runner()
        with self.assertRaises(tr.DuplicateTestError):
            r.register_test("t1", "unit", 4)

    def test_bad_inputs(self):
        r = tr.TestRunner()
        with self.assertRaises(tr.ValidationError):
            r.register_test("", "unit", 1)
        with self.assertRaises(tr.ValidationError):
            r.register_test("x", "unit", 2, labels=["BAD CAPS"])
        with self.assertRaises(tr.ValidationError):
            r.register_test("x", "unit", 3, timeout_ms=-5)
        with self.assertRaises(tr.SeqOrderError):
            r.register_test("y", "unit", 3)  # seq rewind after 3 consumed

    def test_seq_order(self):
        r = tr.TestRunner()
        r.register_test("a", "u", 1)
        with self.assertRaises(tr.SeqOrderError):
            r.register_test("b", "u", 1)
        with self.assertRaises(tr.SeqOrderError):
            r.register_test("c", "u", True)


class TestDiscover(unittest.TestCase):
    def test_all(self):
        r = make_runner()
        d = r.discover(4)
        self.assertEqual(d.count, 3)
        self.assertEqual(d.test_ids, ("t1", "t2", "t3"))

    def test_suite_filter(self):
        r = make_runner()
        d = r.discover(4, suite="unit")
        self.assertEqual(d.test_ids, ("t1", "t2"))

    def test_label_filter(self):
        r = make_runner()
        d = r.discover(4, label="fast")
        self.assertEqual(d.test_ids, ("t1",))

    def test_pattern(self):
        r = make_runner()
        d = r.discover(4, pattern="t1")
        self.assertEqual(d.test_ids, ("t1",))

    def test_empty_result_ok(self):
        r = make_runner()
        d = r.discover(4, pattern="zzz")
        self.assertEqual(d.count, 0)

    def test_determinism(self):
        r = make_runner()
        a = r.discover(4, suite="unit")
        b = r.discover(5, suite="unit")
        self.assertEqual(a.pin, b.pin)  # pin excludes seq


class TestRun(unittest.TestCase):
    def test_run_happy(self):
        r = make_runner()
        plan = r.run(["t1", "t2"], 4)
        self.assertEqual(plan.run_id, "run-1")
        self.assertEqual(plan.test_ids, ("t1", "t2"))
        self.assertEqual(r.run_plan("run-1").pin, plan.pin)

    def test_empty_plan(self):
        r = make_runner()
        with self.assertRaises(tr.EmptyPlanError):
            r.run([], 4)

    def test_unknown_test(self):
        r = make_runner()
        with self.assertRaises(tr.UnknownTestError):
            r.run(["t1", "nope"], 4)

    def test_duplicate_in_plan(self):
        r = make_runner()
        with self.assertRaises(tr.ValidationError):
            r.run(["t1", "t1"], 4)


class TestComplete(unittest.TestCase):
    def _outcomes(self):
        return {
            "t1": {"outcome": "pass", "duration_ms": 5},
            "t2": {"outcome": "fail", "duration_ms": 7, "error": "boom"},
            "t3": {"outcome": "skip"},
        }

    def test_complete_happy(self):
        r = make_runner()
        plan = r.run(["t1", "t2", "t3"], 4)
        rep = r.complete_run(plan.run_id, self._outcomes(), 5)
        self.assertEqual(rep.total, 3)
        self.assertEqual((rep.passed, rep.failed, rep.skipped, rep.errors),
                         (1, 1, 1, 0))
        self.assertEqual(rep.pass_rate_bp, 3333)
        suites = {s: (t, p) for s, t, p in rep.per_suite}
        self.assertEqual(suites, {"unit": (2, 1), "integration": (1, 0)})

    def test_incomplete(self):
        r = make_runner()
        plan = r.run(["t1", "t2"], 4)
        with self.assertRaises(tr.IncompleteRunError):
            r.complete_run(plan.run_id, {"t1": {"outcome": "pass"}}, 5)

    def test_plan_mismatch(self):
        r = make_runner()
        plan = r.run(["t1"], 4)
        with self.assertRaises(tr.PlanMismatchError):
            r.complete_run(plan.run_id,
                           {"t1": {"outcome": "pass"}, "t2": {"outcome": "pass"}}, 5)

    def test_bad_outcome(self):
        r = make_runner()
        plan = r.run(["t1"], 4)
        with self.assertRaises(tr.BadOutcomeError):
            r.complete_run(plan.run_id, {"t1": {"outcome": "maybe"}}, 5)

    def test_double_complete(self):
        r = make_runner()
        plan = r.run(["t1"], 4)
        r.complete_run(plan.run_id, {"t1": {"outcome": "pass"}}, 5)
        with self.assertRaises(tr.TerminalRunError):
            r.complete_run(plan.run_id, {"t1": {"outcome": "pass"}}, 6)

    def test_unknown_run(self):
        r = make_runner()
        with self.assertRaises(tr.UnknownRunError):
            r.complete_run("run-99", {}, 4)

    def test_error_truncation(self):
        r = make_runner()
        plan = r.run(["t1"], 4)
        big = "x" * (tr.MAX_ERROR_CHARS + 100)
        rep = r.complete_run(plan.run_id,
                             {"t1": {"outcome": "error", "error": big}}, 5)
        self.assertEqual(len(rep.outcomes[0].error), tr.MAX_ERROR_CHARS)


class TestReport(unittest.TestCase):
    def test_report_roundtrip(self):
        r = make_runner()
        plan = r.run(["t1"], 4)
        rep = r.complete_run(plan.run_id, {"t1": {"outcome": "pass"}}, 5)
        back = r.report(plan.run_id, 6)
        self.assertEqual(back.pin, rep.pin)

    def test_report_unknown(self):
        r = make_runner()
        with self.assertRaises(tr.UnknownRunError):
            r.report("run-9", 4)


class TestAuditAndMain(unittest.TestCase):
    def test_audit_shapes(self):
        r = make_runner()
        self.assertTrue(all(e["schema"] == "audit.ndjson/1" for e in r.audit_log()))
        ev = tr.test_runner_audit_event("run-started", 1, {"run_id": "run-1"})
        self.assertEqual(ev["kind"], "run-started")
        with self.assertRaises(tr.ValidationError):
            tr.test_runner_audit_event("bogus", 1)

    def test_main(self):
        # exercises module main() path without exiting
        tr.main()


if __name__ == "__main__":
    unittest.main()
