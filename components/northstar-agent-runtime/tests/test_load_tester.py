"""Tests for load_tester: k6-style VU scenario bookkeeping, simulated."""

import threading
import unittest

from load_tester import (
    AUDIT_KINDS,
    LOAD_TESTER_VERSION,
    SCHEMA_PIN,
    THRESHOLD_METRICS,
    THRESHOLD_OPS,
    DuplicateScenarioError,
    LoadTester,
    LoadTesterError,
    ScenarioDefinition,
    ScenarioStage,
    TooManyIterationsError,
    UnknownRunError,
    UnknownScenarioError,
    load_tester_audit_event,
    main,
)


def _tester_with_smoke():
    lt = LoadTester()
    lt.define("smoke", [ScenarioStage(2, 3), (1, 4)], 0)
    return lt


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(LOAD_TESTER_VERSION, "load-tester.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.load-tester.v1")

    def test_threshold_metrics(self):
        self.assertEqual(
            THRESHOLD_METRICS, ("p95_ms", "p99_ms", "avg_ms", "error_rate")
        )

    def test_threshold_ops(self):
        self.assertEqual(THRESHOLD_OPS, ("<", "<=", ">", ">="))

    def test_audit_kinds(self):
        self.assertIn("run-completed", AUDIT_KINDS)
        self.assertIn("rejected", AUDIT_KINDS)


class TestScenarioStage(unittest.TestCase):
    def test_tuple_pair_normalized(self):
        stage = ScenarioStage(10, 5)
        self.assertEqual((stage.duration_seqs, stage.target_vus), (10, 5))

    def test_zero_stage_allowed(self):
        stage = ScenarioStage(0, 0)
        self.assertEqual(stage.duration_seqs, 0)

    def test_negative_duration_refused(self):
        with self.assertRaises(LoadTesterError):
            ScenarioStage(-1, 2)

    def test_negative_vus_refused(self):
        with self.assertRaises(LoadTesterError):
            ScenarioStage(1, -2)

    def test_bool_duration_refused(self):
        with self.assertRaises(LoadTesterError):
            ScenarioStage(True, 2)

    def test_non_int_vus_refused(self):
        with self.assertRaises(LoadTesterError):
            ScenarioStage(1, "2")

    def test_as_dict(self):
        self.assertEqual(
            ScenarioStage(3, 7).as_dict(),
            {"duration_seqs": 3, "target_vus": 7},
        )


class TestDefine(unittest.TestCase):
    def test_define_happy_path(self):
        lt = LoadTester()
        definition = lt.define("s1", [(2, 3)], 0)
        self.assertIsInstance(definition, ScenarioDefinition)
        self.assertEqual(definition.scenario_id, "s1")
        self.assertEqual(definition.version, "load-tester.v1")
        self.assertTrue(definition.digest.startswith("sha256:"))
        self.assertEqual(lt.scenario_ids(), ("s1",))

    def test_define_stage_tuples_accepted(self):
        lt = LoadTester()
        definition = lt.define("s1", [(2, 3), [1, 4]], 0)
        self.assertEqual(len(definition.stages), 2)
        self.assertIsInstance(definition.stages[0], ScenarioStage)

    def test_define_duplicate_refused(self):
        lt = _tester_with_smoke()
        with self.assertRaises(DuplicateScenarioError):
            lt.define("smoke", [(1, 1)], 9)

    def test_define_empty_stages_refused(self):
        with self.assertRaises(LoadTesterError):
            LoadTester().define("s1", [], 0)

    def test_define_empty_id_refused(self):
        with self.assertRaises(LoadTesterError):
            LoadTester().define("", [(1, 1)], 0)

    def test_define_bad_stage_refused(self):
        with self.assertRaises(LoadTesterError):
            LoadTester().define("s1", ["nope"], 0)

    def test_define_bad_seq_refused(self):
        with self.assertRaises(LoadTesterError):
            LoadTester().define("s1", [(1, 1)], -1)
        with self.assertRaises(LoadTesterError):
            LoadTester().define("s1", [(1, 1)], True)

    def test_definition_as_dict(self):
        definition = _tester_with_smoke().define("other", [(1, 2)], 1)
        d = definition.as_dict()
        self.assertEqual(d["schema"], "northstar.load-tester.v1")
        self.assertEqual(d["scenario_id"], "other")
        self.assertEqual(len(d["stages"]), 1)


class TestRun(unittest.TestCase):
    SAMPLES = [(100.0, True), (200.0, True), (300.0, False), (400.0, True)]

    def test_run_aggregates(self):
        report = _tester_with_smoke().run("smoke", 1, samples=self.SAMPLES)
        self.assertEqual(report.run_id, "run-1")
        self.assertEqual(report.total_requests, 4)
        self.assertEqual(report.ok_count, 3)
        self.assertEqual(report.error_count, 1)
        self.assertEqual(report.error_rate, 0.25)
        self.assertEqual(report.min_ms, 100.0)
        self.assertEqual(report.max_ms, 400.0)
        self.assertEqual(report.avg_ms, 250.0)
        self.assertEqual(report.p50_ms, 200.0)
        self.assertEqual(report.p95_ms, 400.0)
        self.assertEqual(report.p99_ms, 400.0)
        self.assertTrue(report.digest.startswith("sha256:"))

    def test_run_ids_monotonic(self):
        lt = _tester_with_smoke()
        r1 = lt.run("smoke", 0, samples=[(1.0, True)])
        r2 = lt.run("smoke", 1, samples=[(1.0, True)])
        self.assertEqual((r1.run_id, r2.run_id), ("run-1", "run-2"))
        self.assertEqual(lt.runs(), ("run-1", "run-2"))

    def test_run_unknown_scenario(self):
        with self.assertRaises(UnknownScenarioError):
            LoadTester().run("nope", 0)

    def test_run_bad_sample_latency(self):
        lt = _tester_with_smoke()
        with self.assertRaises(LoadTesterError):
            lt.run("smoke", 0, samples=[(float("nan"), True)])

    def test_run_non_bool_ok_refused(self):
        lt = _tester_with_smoke()
        with self.assertRaises(LoadTesterError):
            lt.run("smoke", 0, samples=[(100.0, 1)])

    def test_run_malformed_sample_refused(self):
        lt = _tester_with_smoke()
        with self.assertRaises(LoadTesterError):
            lt.run("smoke", 0, samples=[(100.0,)])

    def test_run_empty_samples_zero_aggregates(self):
        report = _tester_with_smoke().run("smoke", 0, samples=[])
        self.assertEqual(report.total_requests, 0)
        self.assertEqual(report.error_rate, 0.0)
        self.assertEqual(report.avg_ms, 0.0)
        self.assertEqual(report.p95_ms, 0.0)

    def test_single_sample_percentiles(self):
        report = _tester_with_smoke().run("smoke", 0, samples=[(123.0, True)])
        self.assertEqual(report.p50_ms, 123.0)
        self.assertEqual(report.p95_ms, 123.0)
        self.assertEqual(report.min_ms, 123.0)

    def test_report_fetch(self):
        lt = _tester_with_smoke()
        report = lt.run("smoke", 0, samples=self.SAMPLES)
        self.assertIs(lt.report("run-1"), report)

    def test_report_unknown_run(self):
        with self.assertRaises(UnknownRunError):
            _tester_with_smoke().report("run-99")

    def test_run_bad_seed_type(self):
        with self.assertRaises(LoadTesterError):
            _tester_with_smoke().run("smoke", 0, seed="not-bytes")


class TestSimulator(unittest.TestCase):
    def test_simulator_iteration_count(self):
        report = _tester_with_smoke().run("smoke", 0, seed=b"seed")
        # (2*3) + (1*4) = 10
        self.assertEqual(report.total_requests, 10)

    def test_simulator_latency_bounds(self):
        report = _tester_with_smoke().run("smoke", 0, seed=b"seed")
        self.assertGreaterEqual(report.min_ms, 50.0)
        self.assertLessEqual(report.max_ms, 500.0)

    def test_simulator_deterministic(self):
        lt = _tester_with_smoke()
        a = lt.run("smoke", 0, seed=b"seed")
        lt2 = _tester_with_smoke()
        b = lt2.run("smoke", 0, seed=b"seed")
        self.assertEqual(a.digest, b.digest)
        self.assertEqual(a.avg_ms, b.avg_ms)

    def test_simulator_seed_sensitive(self):
        lt = _tester_with_smoke()
        a = lt.run("smoke", 0, seed=b"one")
        b = lt.run("smoke", 1, seed=b"two")
        self.assertNotEqual(a.digest, b.digest)

    def test_simulator_ceiling_enforced(self):
        lt = LoadTester()
        lt.define("huge", [ScenarioStage(10_000_000, 10_000_000)], 0)
        with self.assertRaises(TooManyIterationsError):
            lt.run("huge", 0)

    def test_zero_duration_stage_simulates_nothing(self):
        lt = LoadTester()
        lt.define("idle", [(0, 50)], 0)
        report = lt.run("idle", 0)
        self.assertEqual(report.total_requests, 0)


class TestThresholds(unittest.TestCase):
    def test_check_mixed_verdict(self):
        lt = _tester_with_smoke()
        lt.run("smoke", 1, samples=[(100.0, True), (200.0, False)])
        verdict = lt.check(
            "run-1", {"p95_ms": ("<", 500.0), "error_rate": ("<", 0.01)}, 2
        )
        self.assertFalse(verdict.passed)
        by_name = {r.name: r for r in verdict.results}
        self.assertTrue(by_name["p95_ms"].passed)
        self.assertFalse(by_name["error_rate"].passed)
        self.assertEqual(by_name["error_rate"].actual, 0.5)
        self.assertTrue(verdict.digest.startswith("sha256:"))

    def test_check_all_pass(self):
        lt = _tester_with_smoke()
        lt.run("smoke", 1, samples=[(100.0, True)])
        verdict = lt.check(
            "run-1",
            {"avg_ms": ("<=", 100.0), "p99_ms": (">=", 100.0)},
            2,
        )
        self.assertTrue(verdict.passed)

    def test_check_greater_ops(self):
        lt = _tester_with_smoke()
        lt.run("smoke", 1, samples=[(100.0, True)])
        verdict = lt.check("run-1", {"avg_ms": (">", 50.0)}, 0)
        self.assertTrue(verdict.passed)
        verdict2 = lt.check("run-1", {"avg_ms": (">", 100.0)}, 0)
        self.assertFalse(verdict2.passed)

    def test_check_unknown_metric(self):
        lt = _tester_with_smoke()
        lt.run("smoke", 0, samples=[(1.0, True)])
        with self.assertRaises(LoadTesterError):
            lt.check("run-1", {"bogus": ("<", 1.0)}, 0)

    def test_check_unknown_op(self):
        lt = _tester_with_smoke()
        lt.run("smoke", 0, samples=[(1.0, True)])
        with self.assertRaises(LoadTesterError):
            lt.check("run-1", {"p95_ms": ("~", 1.0)}, 0)

    def test_check_unknown_run(self):
        with self.assertRaises(UnknownRunError):
            _tester_with_smoke().check("run-99", {"p95_ms": ("<", 1.0)}, 0)

    def test_check_empty_thresholds_refused(self):
        lt = _tester_with_smoke()
        lt.run("smoke", 0, samples=[(1.0, True)])
        with self.assertRaises(LoadTesterError):
            lt.check("run-1", {}, 0)

    def test_metric_lookup(self):
        lt = _tester_with_smoke()
        report = lt.run("smoke", 0, samples=[(100.0, True)])
        self.assertEqual(report.metric("avg_ms"), 100.0)
        with self.assertRaises(LoadTesterError):
            report.metric("bogus")

    def test_threshold_report_as_dict(self):
        lt = _tester_with_smoke()
        lt.run("smoke", 0, samples=[(100.0, True)])
        verdict = lt.check("run-1", {"p95_ms": ("<", 200.0)}, 0)
        d = verdict.as_dict()
        self.assertEqual(d["schema"], "northstar.load-tester.v1")
        self.assertEqual(d["passed"], True)
        self.assertEqual(len(d["results"]), 1)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        for kind in AUDIT_KINDS:
            event = load_tester_audit_event(kind, 3, {"run_id": "run-1"})
            self.assertEqual(event["schema"], "northstar.audit.ndjson/1")
            self.assertEqual(event["module"], "load-tester.v1")
            self.assertEqual(event["event"], kind)
            self.assertEqual(event["audit_seq"], 3)
            self.assertEqual(event["run_id"], "run-1")

    def test_audit_unknown_kind(self):
        with self.assertRaises(LoadTesterError):
            load_tester_audit_event("bogus", 0, {})

    def test_audit_bad_seq(self):
        with self.assertRaises(LoadTesterError):
            load_tester_audit_event("run-completed", -1, {})


class TestMisc(unittest.TestCase):
    def test_frozen_records(self):
        lt = _tester_with_smoke()
        report = lt.run("smoke", 0, samples=[(1.0, True)])
        with self.assertRaises(Exception):
            report.total_requests = 99  # frozen dataclass

    def test_thread_safety(self):
        lt = LoadTester()
        lt.define("t", [(1, 1)], 0)
        errors = []

        def worker(n):
            try:
                lt.run("t", n, samples=[(float(n), True)])
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(lt.runs()), 8)

    def test_main_self_check(self):
        main()  # must not raise


if __name__ == "__main__":
    unittest.main()
