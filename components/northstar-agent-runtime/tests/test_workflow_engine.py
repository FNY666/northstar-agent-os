"""Tests for workflow_engine (DAG execution with per-step retries)."""

import unittest

from workflow_engine import (
    WORKFLOW_ENGINE_VERSION,
    SCHEMA_PIN,
    CycleError,
    RunFailed,
    StepFailed,
    WorkflowEngine,
    WorkflowError,
    workflow_engine_audit_event,
)


def _engine(spec):
    e = WorkflowEngine()
    e.define(spec)
    return e


class TestVersionPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        e = _engine({"a": {"fn": lambda i, c: 1}})
        report = e.run(seq=0)
        self.assertEqual(report.version, WORKFLOW_ENGINE_VERSION)
        self.assertEqual(report.schema, SCHEMA_PIN)
        self.assertTrue(report.step_reports[0].version, WORKFLOW_ENGINE_VERSION)


class TestDefine(unittest.TestCase):
    def test_topological_order_deterministic(self):
        e = _engine(
            {
                "z": {"fn": lambda i, c: 1, "dependencies": ["a"]},
                "a": {"fn": lambda i, c: 2},
                "m": {"fn": lambda i, c: 3, "dependencies": ["a"]},
            }
        )
        order = e._order
        self.assertEqual(order[0], "a")
        self.assertEqual(set(order[1:]), {"m", "z"})
        self.assertEqual(order[1], "m")  # sorted tie-break

    def test_cycle_rejected(self):
        e = WorkflowEngine()
        with self.assertRaises(CycleError):
            e.define(
                {
                    "a": {"fn": lambda i, c: 1, "dependencies": ["b"]},
                    "b": {"fn": lambda i, c: 2, "dependencies": ["a"]},
                }
            )

    def test_self_dependency_rejected(self):
        e = WorkflowEngine()
        with self.assertRaises(WorkflowError):
            e.define({"a": {"fn": lambda i, c: 1, "dependencies": ["a"]}})

    def test_unknown_dependency_rejected(self):
        e = WorkflowEngine()
        with self.assertRaises(WorkflowError):
            e.define({"a": {"fn": lambda i, c: 1, "dependencies": ["nope"]}})

    def test_non_callable_rejected(self):
        e = WorkflowEngine()
        with self.assertRaises(WorkflowError):
            e.define({"a": {"fn": 42}})

    def test_empty_steps_rejected(self):
        e = WorkflowEngine()
        with self.assertRaises(WorkflowError):
            e.define({})

    def test_double_define_rejected(self):
        e = _engine({"a": {"fn": lambda i, c: 1}})
        with self.assertRaises(WorkflowError):
            e.define({"b": {"fn": lambda i, c: 2}})

    def test_run_before_define_rejected(self):
        e = WorkflowEngine()
        with self.assertRaises(WorkflowError):
            e.run()

    def test_bad_max_attempts_rejected(self):
        e = WorkflowEngine()
        with self.assertRaises(WorkflowError):
            e.define({"a": {"fn": lambda i, c: 1, "max_attempts": 0}})
        e2 = WorkflowEngine()
        with self.assertRaises(WorkflowError):
            e2.define({"a": {"fn": lambda i, c: 1, "max_attempts": True}})


class TestRun(unittest.TestCase):
    def test_happy_path_outputs_threaded(self):
        e = _engine(
            {
                "fetch": {"fn": lambda i, c: {"n": 2}},
                "double": {
                    "fn": lambda i, c: {"n": i["fetch"]["n"] * 2},
                    "dependencies": ["fetch"],
                },
            }
        )
        report = e.run(seq=1)
        self.assertTrue(report.succeeded)
        self.assertIsNone(report.failed_step)
        self.assertEqual(len(report.step_reports), 2)
        self.assertTrue(report.run_digest.startswith("sha256:"))

    def test_context_passed_through(self):
        seen = {}

        def fn(inputs, ctx):
            seen.update(ctx)
            return 1

        e = _engine({"a": {"fn": fn}})
        e.run(context={"user": "u1"}, seq=0)
        self.assertEqual(seen, {"user": "u1"})

    def test_step_failure_raises_run_failed(self):
        def boom(inputs, ctx):
            raise RuntimeError("kaput")

        e = _engine({"a": {"fn": lambda i, c: 1}, "b": {"fn": boom, "dependencies": ["a"]}})
        with self.assertRaises(RunFailed) as cm:
            e.run(seq=0)
        report = cm.exception.report
        self.assertFalse(report.succeeded)
        self.assertEqual(report.failed_step, "b")
        self.assertEqual(len(report.step_reports), 2)  # a succeeded, b failed
        self.assertEqual(report.step_reports[1].error_type, "RuntimeError")

    def test_failed_step_chains_cause(self):
        def boom(inputs, ctx):
            raise ValueError("bad")

        e = _engine({"a": {"fn": boom}})
        with self.assertRaises(RunFailed) as cm:
            e.run(seq=0)
        failure = cm.exception.step_failure
        self.assertIsInstance(failure, StepFailed)
        self.assertIsInstance(failure.last_error, ValueError)

    def test_retry_succeeds_within_budget(self):
        calls = {"n": 0}

        def flaky(inputs, ctx):
            calls["n"] += 1
            if calls["n"] < 3:
                raise RuntimeError("transient")
            return "ok"

        e = _engine(
            {
                "a": {
                    "fn": flaky,
                    "max_attempts": 3,
                    "retry_on": RuntimeError,
                }
            }
        )
        report = e.run(seq=0)
        self.assertTrue(report.succeeded)
        self.assertEqual(report.step_reports[0].attempts_made, 3)
        self.assertEqual(calls["n"], 3)

    def test_retry_exhaustion_fails_run(self):
        def always(inputs, ctx):
            raise RuntimeError("forever")

        e = _engine(
            {"a": {"fn": always, "max_attempts": 2, "retry_on": RuntimeError}}
        )
        with self.assertRaises(RunFailed) as cm:
            e.run(seq=0)
        self.assertEqual(cm.exception.report.step_reports[0].attempts_made, 2)

    def test_non_retryable_error_not_retried(self):
        calls = {"n": 0}

        def boom(inputs, ctx):
            calls["n"] += 1
            raise ValueError("permanent")

        e = _engine(
            {"a": {"fn": boom, "max_attempts": 5, "retry_on": RuntimeError}}
        )
        with self.assertRaises(RunFailed):
            e.run(seq=0)
        self.assertEqual(calls["n"], 1)  # no retry consumed

    def test_backoff_schedule_deterministic(self):
        sleeps = []
        calls = {"n": 0}

        def flaky(inputs, ctx):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("x")
            return 1

        e = _engine(
            {
                "a": {
                    "fn": flaky,
                    "max_attempts": 2,
                    "backoff_ms": 100,
                    "retry_on": RuntimeError,
                }
            }
        )
        e.run(seq=0, sleeper=sleeps.append)
        self.assertEqual(sleeps, [0.1])  # backoff_ms * attempt(1) / 1000

    def test_run_digest_deterministic(self):
        spec = {"a": {"fn": lambda i, c: {"v": 7}}}
        r1 = _engine(spec).run(seq=5)
        r2 = _engine(spec).run(seq=5)
        # run ids differ (run-1 vs run-1 in fresh engines) so digests match
        self.assertEqual(r1.run_digest, r2.run_digest)

    def test_nan_output_rejected(self):
        e = _engine({"a": {"fn": lambda i, c: float("nan")}})
        with self.assertRaises(WorkflowError):
            e.run(seq=0)


class TestRetryRun(unittest.TestCase):
    def _failing_engine(self):
        def boom(inputs, ctx):
            raise RuntimeError("kaput")

        e = _engine({"a": {"fn": lambda i, c: 1}, "b": {"fn": boom, "dependencies": ["a"]}})
        try:
            e.run(seq=0)
        except RunFailed as exc:
            return e, exc.report
        raise AssertionError("should have failed")

    def test_retry_wrong_step_rejected(self):
        e, report = self._failing_engine()
        with self.assertRaises(WorkflowError):
            e.retry_run(report, "a", seq=1)

    def test_retry_succeeded_run_rejected(self):
        e = _engine({"a": {"fn": lambda i, c: 1}})
        ok = e.run(seq=0)
        with self.assertRaises(WorkflowError):
            e.retry_run(ok, "a", seq=1)

    def test_retry_with_dependency_rejected_honestly(self):
        # step b failed and has a dependency: retry requires upstream
        # outputs which the engine does not retain -> fail-closed.
        e, report = self._failing_engine()
        with self.assertRaises(WorkflowError):
            e.retry_run(report, "b", seq=1)

    def test_retry_independent_failed_step(self):
        calls = {"n": 0}

        def flaky(inputs, ctx):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("first")
            return "recovered"

        e = _engine({"a": {"fn": flaky, "max_attempts": 1, "retry_on": RuntimeError}})
        try:
            e.run(seq=0)
            raise AssertionError("should have failed")
        except RunFailed as exc:
            report2 = e.retry_run(exc.report, "a", seq=1)
        self.assertTrue(report2.succeeded)
        self.assertEqual(report2.step_order, ("a",))


class TestFrozenRecords(unittest.TestCase):
    def test_step_report_frozen(self):
        e = _engine({"a": {"fn": lambda i, c: 1}})
        report = e.run(seq=0)
        with self.assertRaises(AttributeError):
            report.step_reports[0].succeeded = False  # type: ignore

    def test_output_digest_binds_content(self):
        e1 = _engine({"a": {"fn": lambda i, c: {"x": 1}}})
        e2 = _engine({"a": {"fn": lambda i, c: {"x": 2}}})
        self.assertNotEqual(
            e1.run(seq=0).step_reports[0].output_digest,
            e2.run(seq=0).step_reports[0].output_digest,
        )


class TestAudit(unittest.TestCase):
    def test_all_kinds(self):
        for kind in (
            "defined",
            "step-started",
            "step-succeeded",
            "step-failed",
            "run-completed",
            "step-retried",
            "rejected",
        ):
            rec = workflow_engine_audit_event(kind, 3, step_id="s", run_id="r")
            self.assertEqual(rec["kind"], kind)
            self.assertEqual(rec["format"], "audit.ndjson/1")
            self.assertEqual(rec["schema"], SCHEMA_PIN)

    def test_bad_kind_rejected(self):
        with self.assertRaises(ValueError):
            workflow_engine_audit_event("bogus", 0)

    def test_bad_seq_rejected(self):
        with self.assertRaises(WorkflowError):
            workflow_engine_audit_event("defined", -1)


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        import workflow_engine as mod

        mod.main()  # asserts internally


if __name__ == "__main__":
    unittest.main()
