"""Tests for slo_tracker: SLO objectives, error budgets, burn rates."""

import unittest

from slo_tracker import (
    SCHEMA_PIN,
    SLO_TRACKER_VERSION,
    DuplicateObjectiveError,
    ObjectiveRecord,
    SeqOrderError,
    SLOTracker,
    UnknownObjectiveError,
    slo_tracker_audit_event,
)


class TestDefineObjective(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(SLO_TRACKER_VERSION, "slo-tracker.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.slo-tracker.v1")

    def test_define_happy_path(self):
        t = SLOTracker()
        rec = t.define_objective("api", 0.99, 100, seq=1)
        self.assertIsInstance(rec, ObjectiveRecord)
        self.assertEqual(rec.objective_id, "api")
        self.assertEqual(rec.target, 0.99)
        self.assertEqual(rec.window_events, 100)
        self.assertAlmostEqual(rec.allowed_error_ratio, 0.01)
        self.assertAlmostEqual(rec.allowed_failures, 1.0)
        self.assertEqual(rec.seq, 1)
        self.assertEqual(rec.version, "slo-tracker.v1")
        self.assertEqual(rec.schema, "northstar.slo-tracker.v1")
        self.assertEqual(t.objectives(), ("api",))
        self.assertEqual(t.objective("api").as_dict()["objective_id"], "api")

    def test_define_duplicate_refused(self):
        t = SLOTracker()
        t.define_objective("api", 0.99, 100, seq=1)
        with self.assertRaises(DuplicateObjectiveError):
            t.define_objective("api", 0.999, 50, seq=2)

    def test_define_validation(self):
        t = SLOTracker()
        with self.assertRaises(Exception):
            t.define_objective("", 0.99, 100, seq=1)
        with self.assertRaises(Exception):
            t.define_objective("api", 1.0, 100, seq=1)
        with self.assertRaises(Exception):
            t.define_objective("api", 0.0, 100, seq=1)
        with self.assertRaises(Exception):
            t.define_objective("api", 0.99, 0, seq=1)
        with self.assertRaises(Exception):
            t.define_objective("api", 0.99, 100, seq=-1)
        with self.assertRaises(Exception):
            t.define_objective("api", True, 100, seq=1)
        with self.assertRaises(Exception):
            t.define_objective("api", 0.99, True, seq=1)

    def test_seq_must_increase(self):
        t = SLOTracker()
        t.define_objective("a", 0.99, 100, seq=5)
        with self.assertRaises(SeqOrderError):
            t.define_objective("b", 0.99, 100, seq=5)
        with self.assertRaises(SeqOrderError):
            t.record("a", True, seq=3)
        t.define_objective("b", 0.99, 100, seq=6)


class TestRecord(unittest.TestCase):
    def test_record_unknown_objective(self):
        t = SLOTracker()
        with self.assertRaises(UnknownObjectiveError):
            t.record("nope", True, seq=1)

    def test_record_success_must_be_bool(self):
        t = SLOTracker()
        t.define_objective("api", 0.99, 100, seq=1)
        with self.assertRaises(Exception):
            t.record("api", 1, seq=2)
        with self.assertRaises(Exception):
            t.record("api", "yes", seq=2)

    def test_rolling_window_evicts_oldest(self):
        t = SLOTracker()
        t.define_objective("api", 0.9, 4, seq=0)
        t.record("api", False, seq=1)
        t.record("api", False, seq=2)
        t.record("api", True, seq=3)
        t.record("api", True, seq=4)
        t.record("api", True, seq=5)
        b = t.budget("api", seq=6)
        self.assertEqual(b.events_in_window, 4)
        self.assertEqual(b.observed_failures, 1)


class TestBudget(unittest.TestCase):
    def test_budget_full_remaining(self):
        t = SLOTracker()
        t.define_objective("api", 0.99, 100, seq=0)
        for i in range(10):
            t.record("api", True, seq=i + 1)
        b = t.budget("api", seq=11)
        self.assertEqual(b.observed_failures, 0)
        self.assertEqual(b.consumed, 0.0)
        self.assertEqual(b.remaining, 1.0)
        self.assertFalse(b.exhausted)
        self.assertEqual(b.events_in_window, 10)

    def test_budget_consumed_and_exhausted(self):
        t = SLOTracker()
        t.define_objective("api", 0.99, 100, seq=0)
        for i in range(98):
            t.record("api", True, seq=i + 1)
        t.record("api", False, seq=99)
        b = t.budget("api", seq=100)
        self.assertEqual(b.observed_failures, 1)
        self.assertAlmostEqual(b.consumed, 1.0)
        self.assertAlmostEqual(b.remaining, 0.0)
        self.assertFalse(b.exhausted)
        t.record("api", False, seq=101)
        b2 = t.budget("api", seq=102)
        self.assertTrue(b2.exhausted)
        self.assertLess(b2.remaining, 0.0)
        d = b2.as_dict()
        self.assertEqual(d["schema"], "northstar.slo-tracker.v1")
        self.assertTrue(d["exhausted"])

    def test_budget_unknown_objective(self):
        t = SLOTracker()
        with self.assertRaises(UnknownObjectiveError):
            t.budget("nope", seq=1)


class TestBurnRate(unittest.TestCase):
    def test_burn_rate_empty_window_zero(self):
        t = SLOTracker()
        t.define_objective("api", 0.99, 100, seq=0)
        r = t.burn_rate("api", seq=1)
        self.assertEqual(r.burn_rate, 0.0)
        self.assertEqual(r.observed_error_ratio, 0.0)
        self.assertEqual(r.events_in_window, 0)

    def test_burn_rate_exact_pace(self):
        t = SLOTracker()
        t.define_objective("api", 0.99, 100, seq=0)
        for i in range(99):
            t.record("api", True, seq=i + 1)
        t.record("api", False, seq=100)
        r = t.burn_rate("api", seq=101)
        self.assertAlmostEqual(r.burn_rate, 1.0, places=9)
        self.assertEqual(r.seq, 101)

    def test_burn_rate_fast(self):
        t = SLOTracker()
        t.define_objective("api", 0.99, 100, seq=0)
        for i in range(90):
            t.record("api", True, seq=i + 1)
        for i in range(10):
            t.record("api", False, seq=91 + i)
        r = t.burn_rate("api", seq=101)
        self.assertAlmostEqual(r.burn_rate, 10.0, places=9)
        d = r.as_dict()
        self.assertEqual(d["version"], "slo-tracker.v1")

    def test_burn_rate_unknown_objective(self):
        t = SLOTracker()
        with self.assertRaises(UnknownObjectiveError):
            t.burn_rate("nope", seq=1)


class TestStatusAndAudit(unittest.TestCase):
    def test_status_combined(self):
        t = SLOTracker()
        t.define_objective("api", 0.999, 1000, seq=0)
        for i in range(100):
            t.record("api", True, seq=i + 1)
        s = t.status("api", seq=101)
        self.assertEqual(s.budget.observed_failures, 0)
        self.assertEqual(s.burn.burn_rate, 0.0)
        self.assertEqual(s.version, "slo-tracker.v1")
        d = s.as_dict()
        self.assertIn("budget", d)
        self.assertIn("burn", d)

    def test_audit_events(self):
        e = slo_tracker_audit_event("objective-defined", seq=1, detail={"objective_id": "api"})
        self.assertEqual(e["schema"], "audit.ndjson/1")
        self.assertEqual(e["kind"], "slo-tracker.objective-defined")
        self.assertEqual(e["module_version"], "slo-tracker.v1")
        e2 = slo_tracker_audit_event("event-recorded", seq=2)
        self.assertEqual(e2["detail"], {})
        with self.assertRaises(Exception):
            slo_tracker_audit_event("bogus-kind", seq=3)
        with self.assertRaises(Exception):
            slo_tracker_audit_event("rejected", seq=-1)

    def test_thread_safety_smoke(self):
        import threading

        t = SLOTracker()
        t.define_objective("api", 0.99, 1000, seq=0)
        counter = [1]

        def worker():
            for _ in range(50):
                with threading.Lock():
                    s = counter[0]
                    counter[0] += 1
                t.record("api", True, seq=s)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        b = t.budget("api", seq=counter[0])
        self.assertEqual(b.events_in_window, 200)
        self.assertEqual(b.observed_failures, 0)


if __name__ == "__main__":
    unittest.main()
