"""Tests for experiment_tracker."""

import unittest

from experiment_tracker import (
    BestResult,
    ComparisonReport,
    DuplicateRunError,
    EmptyTrackerError,
    ExperimentTracker,
    ExperimentTrackerError,
    MetricComparison,
    RunRecord,
    UnknownMetricError,
    UnknownRunError,
    EXPERIMENT_TRACKER_VERSION,
    EXPERIMENT_TRACKER_SCHEMA,
    experiment_tracker_audit_event,
)


def _tracker():
    return ExperimentTracker()


class TestConstruction(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(EXPERIMENT_TRACKER_VERSION, "experiment-tracker.v1")
        self.assertEqual(EXPERIMENT_TRACKER_SCHEMA, "northstar.experiment-tracker.v1")


class TestLogRun(unittest.TestCase):
    def test_log_run_shape(self):
        rec = _tracker().log_run({"lr": 0.01}, {"acc": 0.9}, seq=1)
        self.assertIsInstance(rec, RunRecord)
        self.assertEqual(rec.run_id, "run-1")
        self.assertEqual(rec.params_dict(), {"lr": 0.01})
        self.assertEqual(rec.metrics_dict(), {"acc": 0.9})
        self.assertEqual(rec.seq, 1)
        self.assertEqual(rec.version, "experiment-tracker.v1")
        self.assertEqual(rec.schema, "northstar.experiment-tracker.v1")

    def test_auto_run_id_increments(self):
        t = _tracker()
        a = t.log_run({}, {"m": 1.0}, seq=1)
        b = t.log_run({}, {"m": 2.0}, seq=2)
        self.assertEqual((a.run_id, b.run_id), ("run-1", "run-2"))

    def test_explicit_run_id(self):
        rec = _tracker().log_run({}, {"m": 1.0}, seq=1, run_id="exp-alpha")
        self.assertEqual(rec.run_id, "exp-alpha")

    def test_duplicate_run_id_rejected(self):
        t = _tracker()
        t.log_run({}, {"m": 1.0}, seq=1, run_id="x")
        with self.assertRaises(DuplicateRunError):
            t.log_run({}, {"m": 2.0}, seq=2, run_id="x")

    def test_params_must_be_mapping(self):
        with self.assertRaises(TypeError):
            _tracker().log_run([("lr", 0.1)], {"m": 1.0}, seq=1)

    def test_params_non_str_key_rejected(self):
        with self.assertRaises(TypeError):
            _tracker().log_run({1: 0.1}, {"m": 1.0}, seq=1)

    def test_params_empty_key_rejected(self):
        with self.assertRaises(ValueError):
            _tracker().log_run({"": 0.1}, {"m": 1.0}, seq=1)

    def test_params_nan_rejected(self):
        with self.assertRaises(ValueError):
            _tracker().log_run({"lr": float("nan")}, {"m": 1.0}, seq=1)

    def test_metrics_bool_rejected(self):
        with self.assertRaises(TypeError):
            _tracker().log_run({}, {"m": True}, seq=1)

    def test_metrics_nan_rejected(self):
        with self.assertRaises(ValueError):
            _tracker().log_run({}, {"m": float("nan")}, seq=1)

    def test_metrics_inf_rejected(self):
        with self.assertRaises(ValueError):
            _tracker().log_run({}, {"m": float("inf")}, seq=1)

    def test_metrics_non_numeric_rejected(self):
        with self.assertRaises(TypeError):
            _tracker().log_run({}, {"m": "high"}, seq=1)

    def test_bad_seq_rejected(self):
        t = _tracker()
        for bad in (-1, True, "1", 1.0, None):
            with self.assertRaises((TypeError, ValueError)):
                t.log_run({}, {"m": 1.0}, seq=bad)

    def test_run_id_must_be_non_empty_str(self):
        t = _tracker()
        with self.assertRaises(TypeError):
            t.log_run({}, {"m": 1.0}, seq=1, run_id=7)
        with self.assertRaises(ValueError):
            t.log_run({}, {"m": 1.0}, seq=1, run_id="")

    def test_digest_pin_shape(self):
        rec = _tracker().log_run({"lr": 0.1}, {"acc": 0.9}, seq=1)
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(len(rec.digest), 71)

    def test_params_determinism(self):
        t = _tracker()
        a = t.log_run({"b": 2, "a": 1}, {"m": 1.0}, seq=1, run_id="r1")
        self.assertEqual(a.params, (("a", 1), ("b", 2)))


class TestViews(unittest.TestCase):
    def test_get_and_count(self):
        t = _tracker()
        t.log_run({}, {"m": 1.0}, seq=1, run_id="r1")
        t.log_run({}, {"m": 2.0}, seq=2, run_id="r2")
        self.assertEqual(t.run_count(), 2)
        self.assertEqual(t.run_ids(), ("r1", "r2"))
        self.assertEqual(t.get("r1").metrics_dict(), {"m": 1.0})

    def test_get_unknown_raises(self):
        with self.assertRaises(UnknownRunError):
            _tracker().get("nope")


class TestCompare(unittest.TestCase):
    def test_compare_shape(self):
        t = _tracker()
        t.log_run({}, {"acc": 0.9, "loss": 0.2}, seq=1, run_id="a")
        t.log_run({}, {"acc": 0.95}, seq=2, run_id="b")
        report = t.compare(["a", "b"], seq=3)
        self.assertIsInstance(report, ComparisonReport)
        self.assertEqual(report.run_ids, ("a", "b"))
        self.assertEqual(report.metrics(), ("acc", "loss"))
        acc = report.comparisons[0]
        self.assertIsInstance(acc, MetricComparison)
        self.assertEqual(acc.values, (0.9, 0.95))
        self.assertEqual(acc.best_run_id, "b")
        loss = report.comparisons[1]
        self.assertEqual(loss.values, (0.2, None))
        self.assertEqual(loss.best_run_id, "a")

    def test_compare_unknown_run(self):
        t = _tracker()
        t.log_run({}, {"m": 1.0}, seq=1, run_id="a")
        with self.assertRaises(UnknownRunError):
            t.compare(["a", "ghost"], seq=2)

    def test_compare_empty_list(self):
        with self.assertRaises(ExperimentTrackerError):
            _tracker().compare([], seq=1)

    def test_compare_duplicate_ids(self):
        t = _tracker()
        t.log_run({}, {"m": 1.0}, seq=1, run_id="a")
        with self.assertRaises(ExperimentTrackerError):
            t.compare(["a", "a"], seq=2)

    def test_compare_empty_tracker(self):
        with self.assertRaises(EmptyTrackerError):
            _tracker().compare(["a"], seq=1)


class TestBest(unittest.TestCase):
    def test_best_max(self):
        t = _tracker()
        t.log_run({}, {"acc": 0.9}, seq=1, run_id="a")
        t.log_run({}, {"acc": 0.95}, seq=2, run_id="b")
        result = t.best("acc", seq=3)
        self.assertIsInstance(result, BestResult)
        self.assertEqual(result.run_id, "b")
        self.assertEqual(result.value, 0.95)
        self.assertEqual(result.mode, "max")
        self.assertEqual(result.candidates, 2)

    def test_best_min(self):
        t = _tracker()
        t.log_run({}, {"loss": 0.2}, seq=1, run_id="a")
        t.log_run({}, {"loss": 0.1}, seq=2, run_id="b")
        result = t.best("loss", mode="min", seq=3)
        self.assertEqual(result.run_id, "b")
        self.assertEqual(result.value, 0.1)

    def test_best_skips_missing_metric(self):
        t = _tracker()
        t.log_run({}, {"other": 1.0}, seq=1, run_id="a")
        t.log_run({}, {"acc": 0.8}, seq=2, run_id="b")
        result = t.best("acc", seq=3)
        self.assertEqual(result.run_id, "b")
        self.assertEqual(result.candidates, 1)

    def test_best_tie_breaks_by_earliest_seq(self):
        t = _tracker()
        t.log_run({}, {"acc": 0.9}, seq=5, run_id="late")
        t.log_run({}, {"acc": 0.9}, seq=2, run_id="early")
        result = t.best("acc", seq=9)
        self.assertEqual(result.run_id, "early")

    def test_best_unknown_metric(self):
        t = _tracker()
        t.log_run({}, {"acc": 0.9}, seq=1, run_id="a")
        with self.assertRaises(UnknownMetricError):
            t.best("nope", seq=2)

    def test_best_empty_tracker(self):
        with self.assertRaises(EmptyTrackerError):
            _tracker().best("acc", seq=1)

    def test_best_bad_mode(self):
        t = _tracker()
        t.log_run({}, {"acc": 0.9}, seq=1, run_id="a")
        with self.assertRaises(ValueError):
            t.best("acc", mode="median", seq=2)


class TestAuditEvent(unittest.TestCase):
    def test_run_logged_shape(self):
        ev = experiment_tracker_audit_event("run-logged", 7, run_id="r1")
        self.assertEqual(ev["event"], "experiment-tracker")
        self.assertEqual(ev["kind"], "run-logged")
        self.assertEqual(ev["audit_seq"], 7)
        self.assertEqual(ev["run_id"], "r1")
        self.assertEqual(ev["schema"], "audit.ndjson/1")

    def test_compared_shape(self):
        ev = experiment_tracker_audit_event("compared", 8)
        self.assertEqual(ev["kind"], "compared")
        self.assertNotIn("run_id", ev)

    def test_best_selected_shape(self):
        ev = experiment_tracker_audit_event("best-selected", 9, metric="acc")
        self.assertEqual(ev["kind"], "best-selected")
        self.assertEqual(ev["metric"], "acc")

    def test_bad_kind_rejected(self):
        with self.assertRaises(ValueError):
            experiment_tracker_audit_event("renamed", 1)

    def test_bad_seq_rejected(self):
        with self.assertRaises(TypeError):
            experiment_tracker_audit_event("run-logged", True)


class TestRecords(unittest.TestCase):
    def test_run_record_frozen(self):
        rec = _tracker().log_run({"lr": 0.1}, {"acc": 0.9}, seq=1)
        with self.assertRaises(AttributeError):
            rec.seq = 2  # type: ignore[misc]

    def test_run_record_as_dict(self):
        rec = _tracker().log_run({"lr": 0.1}, {"acc": 0.9}, seq=1)
        d = rec.as_dict()
        self.assertEqual(d["run_id"], "run-1")
        self.assertEqual(d["metrics"], {"acc": 0.9})
        self.assertEqual(d["version"], "experiment-tracker.v1")


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        import experiment_tracker

        experiment_tracker.main()


if __name__ == "__main__":
    unittest.main()
