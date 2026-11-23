"""Tests for benchmark_runner: hyperfine-style benchmark bookkeeping."""

import ast
import unittest
from pathlib import Path

from benchmark_runner import (
    BENCHMARK_RUNNER_VERSION,
    SCHEMA_PIN,
    BadDurationError,
    BadThresholdError,
    BenchmarkRunner,
    DuplicateBenchmarkError,
    InsufficientRunsError,
    NoBaselineError,
    NoRunError,
    SCHEMA_PIN as _SP,
    SeqOrderError,
    UnknownBenchmarkError,
    ValidationError,
    benchmark_runner_audit_event,
)

MODULE = Path(__file__).parent.parent / "benchmark_runner.py"
TEST = Path(__file__)


def make_runner():
    r = BenchmarkRunner()
    r.register("hash", 1, cmdline="sha256sum f", runs=5, warmup_runs=2)
    return r


class TestPins(unittest.TestCase):
    def test_version_and_schema(self):
        self.assertEqual(BENCHMARK_RUNNER_VERSION, "benchmark-runner.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.benchmark-runner.v1")
        self.assertEqual(_SP, SCHEMA_PIN)

    def test_stdlib_only(self):
        tree = ast.parse(MODULE.read_text())
        allowed = {
            "__future__", "hashlib", "math", "threading", "dataclasses",
            "fractions", "typing", "canonical_json", "json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(node.module.split(".")[0], allowed)


class TestRegister(unittest.TestCase):
    def test_roundtrip(self):
        r = make_runner()
        spec = r.spec("hash")
        self.assertEqual(spec.cmdline, "sha256sum f")
        self.assertEqual(spec.runs, 5)
        self.assertEqual(spec.warmup_runs, 2)
        self.assertTrue(spec.spec_pin.startswith("sha256:"))
        self.assertIn("hash", r.spec_names())

    def test_duplicate_refused(self):
        r = make_runner()
        with self.assertRaises(DuplicateBenchmarkError):
            r.register("hash", 2)

    def test_bad_inputs(self):
        r = BenchmarkRunner()
        with self.assertRaises(ValidationError):
            r.register("", 1)
        with self.assertRaises(ValidationError):
            r.register("ok", 2, runs=2)  # below MIN_RUNS
        with self.assertRaises(ValidationError):
            r.register("ok", 3, runs=True)
        with self.assertRaises(UnknownBenchmarkError):
            r.spec("nope")

    def test_seq_order(self):
        r = BenchmarkRunner()
        r.register("a", 1)
        with self.assertRaises(SeqOrderError):
            r.register("b", 1)
        with self.assertRaises(ValidationError):
            r.register("c", True)


class TestBench(unittest.TestCase):
    def test_stats_math(self):
        r = make_runner()
        run = r.bench("hash", 2, [100, 200, 300, 400, 500])
        self.assertEqual(run.count, 5)
        self.assertEqual((run.min_us, run.max_us), (100, 500))
        self.assertEqual(run.median_us, 300)
        self.assertEqual(run.mean_us, 300)
        self.assertEqual(run.p90_us, 500)
        self.assertEqual(run.stddev_us, 141)  # isqrt(20000) = 141
        self.assertTrue(run.run_pin.startswith("sha256:"))

    def test_even_median(self):
        r = make_runner()
        run = r.bench("hash", 2, [100, 200, 300, 400, 500])
        # even-count median via a second spec
        r.register("even", 3, runs=4)
        run2 = r.bench("even", 4, [100, 200, 300, 400])
        self.assertEqual(run2.median_us, 250)
        self.assertEqual(run.mean_us, 300)

    def test_durations_kept_and_sorted(self):
        r = make_runner()
        run = r.bench("hash", 2, [500, 100, 400, 200, 300])
        self.assertEqual(run.durations_us, (500, 100, 400, 200, 300))
        self.assertEqual(run.median_us, 300)

    def test_digest_determinism(self):
        r1, r2 = make_runner(), make_runner()
        a = r1.bench("hash", 2, [100, 200, 300, 400, 500])
        b = r2.bench("hash", 2, [100, 200, 300, 400, 500])
        self.assertEqual(a.run_pin, b.run_pin)

    def test_refusals(self):
        r = make_runner()
        with self.assertRaises(UnknownBenchmarkError):
            r.bench("nope", 2, [100, 200, 300, 400, 500])
        with self.assertRaises(BadDurationError):
            r.bench("hash", 3, [100, 200, 300.5, 400, 500])  # float
        with self.assertRaises(BadDurationError):
            r.bench("hash", 4, [100, 200, True, 400, 500])  # bool
        with self.assertRaises(BadDurationError):
            r.bench("hash", 5, [100, 200, 0, 400, 500])  # zero
        with self.assertRaises(BadDurationError):
            r.bench("hash", 6, [100, 200, -5, 400, 500])  # negative
        with self.assertRaises(InsufficientRunsError):
            r.bench("hash", 7, [100, 200, 300])  # fewer than 5
        with self.assertRaises(SeqOrderError):
            r.bench("hash", 2, [100, 200, 300, 400, 500])  # rewind
        with self.assertRaises(BadDurationError):
            r.bench("hash", 8, "notalist")


class TestCompare(unittest.TestCase):
    def test_a_faster(self):
        r = make_runner()
        r.register("sort", 2, runs=5)
        r.bench("hash", 3, [100, 110, 120, 130, 140])
        r.bench("sort", 4, [600, 610, 620, 630, 640])
        rep = r.compare("hash", "sort", 5)
        self.assertEqual(rep.verdict, "a-faster")
        self.assertEqual((rep.ratio_num, rep.ratio_den), (6, 31))  # Fraction reduced
        self.assertTrue(rep.report_pin.startswith("sha256:"))

    def test_b_faster(self):
        r = make_runner()
        r.register("sort", 2, runs=5)
        r.bench("hash", 3, [600, 610, 620, 630, 640])
        r.bench("sort", 4, [100, 110, 120, 130, 140])
        rep = r.compare("hash", "sort", 5)
        self.assertEqual(rep.verdict, "b-faster")

    def test_indistinguishable(self):
        r = make_runner()
        r.register("sort", 2, runs=5)
        r.bench("hash", 3, [100, 110, 120, 130, 140])
        r.bench("sort", 4, [101, 111, 121, 131, 141])
        rep = r.compare("hash", "sort", 5)
        self.assertEqual(rep.verdict, "indistinguishable")

    def test_margin_band(self):
        r = make_runner()
        r.register("sort", 2, runs=5)
        r.bench("hash", 3, [100, 100, 100, 100, 100])
        r.bench("sort", 4, [110, 110, 110, 110, 110])  # 10% slower
        # margin 2: outside band -> a-faster (hash is the fast one)
        self.assertEqual(r.compare("hash", "sort", 5, margin_pct=2).verdict, "a-faster")
        # margin 20: inside band -> indistinguishable
        self.assertEqual(
            r.compare("hash", "sort", 6, margin_pct=20).verdict, "indistinguishable"
        )

    def test_missing_run(self):
        r = make_runner()
        r.register("sort", 2, runs=5)
        r.bench("hash", 3, [100, 110, 120, 130, 140])
        with self.assertRaises(NoRunError):
            r.compare("hash", "sort", 4)
        with self.assertRaises(BadThresholdError):
            r.compare("hash", "hash", 5, margin_pct=99)


class TestRegress(unittest.TestCase):
    def _based(self):
        r = make_runner()
        r.bench("hash", 2, [290, 295, 300, 305, 310])  # median 300
        r.set_baseline("hash", 3)
        return r

    def test_regressed(self):
        r = self._based()
        r.bench("hash", 4, [390, 395, 400, 405, 410])  # median 400: +33%
        rep = r.regress("hash", 5)
        self.assertEqual(rep.verdict, "regressed")
        self.assertEqual((rep.delta_pct_num, rep.delta_pct_den), (100, 3))
        self.assertTrue(rep.report_pin.startswith("sha256:"))

    def test_improved(self):
        r = self._based()
        r.bench("hash", 4, [190, 195, 200, 205, 210])  # median 200: -33%
        rep = r.regress("hash", 5)
        self.assertEqual(rep.verdict, "improved")

    def test_stable(self):
        r = self._based()
        r.bench("hash", 4, [305, 308, 310, 312, 315])  # median 310: +3.3%
        rep = r.regress("hash", 5)
        self.assertEqual(rep.verdict, "stable")

    def test_threshold_boundary(self):
        r = self._based()
        r.bench("hash", 4, [315, 315, 315, 315, 315])  # exactly +5%
        rep = r.regress("hash", 5, threshold_pct=5)
        self.assertEqual(rep.verdict, "regressed")
        rep2 = r.regress("hash", 6, threshold_pct=6)
        self.assertEqual(rep2.verdict, "stable")

    def test_no_baseline(self):
        r = make_runner()
        r.bench("hash", 2, [100, 200, 300, 400, 500])
        with self.assertRaises(NoBaselineError):
            r.regress("hash", 3)
        with self.assertRaises(NoRunError):
            make_runner().set_baseline("hash", 2)  # never benched
        with self.assertRaises(BadThresholdError):
            self._based().regress("hash", 5, threshold_pct=-1)


class TestViewsAndAudit(unittest.TestCase):
    def test_views(self):
        r = make_runner()
        run = r.bench("hash", 2, [100, 200, 300, 400, 500])
        self.assertEqual(r.run(run.run_id), run)
        self.assertEqual(r.latest("hash"), run)
        self.assertEqual(r.runs("hash"), (run.run_id,))
        r.set_baseline("hash", 3)
        self.assertEqual(r.baseline("hash").run_id, run.run_id)
        with self.assertRaises(NoRunError):
            r.run("run-999")
        with self.assertRaises(UnknownBenchmarkError):
            r.runs("nope")

    def test_audit_shapes(self):
        r = make_runner()
        r.bench("hash", 2, [100, 200, 300, 400, 500])
        log = r.audit_log()
        self.assertEqual([e["kind"] for e in log],
                         ["benchmark-registered", "benchmark-run"])
        self.assertTrue(all(e["schema"] == "audit.ndjson/1" for e in log))
        self.assertTrue(all(e["module"] == "benchmark_runner" for e in log))
        ev = benchmark_runner_audit_event("rejected", 9, {"why": "x"})
        self.assertEqual(ev["kind"], "rejected")
        with self.assertRaises(ValidationError):
            benchmark_runner_audit_event("nope", 9, {})
        with self.assertRaises(ValidationError):
            benchmark_runner_audit_event("compared", True, {})

    def test_main(self):
        import benchmark_runner

        benchmark_runner.main()  # must not raise


if __name__ == "__main__":
    unittest.main()
