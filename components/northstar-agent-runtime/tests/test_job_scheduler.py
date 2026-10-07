"""Tests for job_scheduler.py -- 15 targeted tests."""

import unittest

from job_scheduler import (
    VERSION,
    SCHEMA,
    JobScheduler,
    CronSpec,
    OneShotSpec,
    JobRecord,
    DueReport,
    FireEvent,
    SchedulerError,
    CronParseError,
    DuplicateJobError,
    UnknownJobError,
    parse_cron,
    job_scheduler_audit_event,
)

# 2021-01-01 00:00:00 UTC == Friday.
T0 = 1_609_459_200


class TestPins(unittest.TestCase):
    def test_version_schema(self):
        self.assertEqual(VERSION, "job-scheduler.v1")
        self.assertEqual(SCHEMA, "northstar.job-scheduler.v1")


class TestParseCron(unittest.TestCase):
    def test_star_star(self):
        spec = parse_cron("* * * * *")
        self.assertEqual(len(spec.minute), 60)
        self.assertEqual(len(spec.day_of_week), 7)

    def test_exact_and_step(self):
        spec = parse_cron("*/15 9-17 * * 1-5")
        self.assertEqual(spec.minute, frozenset({0, 15, 30, 45}))
        self.assertEqual(spec.hour, frozenset(range(9, 18)))
        self.assertEqual(spec.day_of_week, frozenset({1, 2, 3, 4, 5}))

    def test_aliases(self):
        spec = parse_cron("0 0 * jan mon")
        self.assertEqual(spec.month, frozenset({1}))
        self.assertEqual(spec.day_of_week, frozenset({1}))

    def test_bad_field_count(self):
        with self.assertRaises(CronParseError):
            parse_cron("* * * *")
        with self.assertRaises(CronParseError):
            parse_cron("* * * * * *")

    def test_bad_value(self):
        with self.assertRaises(CronParseError):
            parse_cron("61 * * * *")
        with self.assertRaises(CronParseError):
            parse_cron("*/0 * * * *")
        with self.assertRaises(CronParseError):
            parse_cron("5-3 * * * *")


class TestMatches(unittest.TestCase):
    def test_match_midnight(self):
        spec = parse_cron("0 0 * * *")
        self.assertTrue(spec.matches(T0))
        self.assertFalse(spec.matches(T0 + 60))

    def test_dow_mapping(self):
        # 2021-01-01 is Friday -> cron dow 5.
        spec = parse_cron("0 0 * * 5")
        self.assertTrue(spec.matches(T0))
        self.assertFalse(parse_cron("0 0 * * 6").matches(T0))


class TestScheduler(unittest.TestCase):
    def setUp(self):
        self.sched = JobScheduler()

    def test_schedule_and_duplicate(self):
        record = self.sched.schedule("j", parse_cron("0 * * * *"), 1)
        self.assertIsInstance(record, JobRecord)
        self.assertTrue(record.digest.startswith("sha256:"))
        with self.assertRaises(DuplicateJobError):
            self.sched.schedule("j", parse_cron("0 * * * *"), 2)

    def test_due_cron_once_per_tick(self):
        self.sched.schedule("hourly", parse_cron("0 * * * *"), 0)
        first = self.sched.due(T0, 1)
        self.assertEqual(first.due_job_ids, ("hourly",))
        second = self.sched.due(T0, 2)
        self.assertEqual(second.due_job_ids, ())
        self.assertIsInstance(first, DueReport)

    def test_one_shot_consumed(self):
        self.sched.schedule("once", OneShotSpec(T0 + 3600), 0)
        self.assertEqual(self.sched.due(T0, 1).due_job_ids, ())
        report = self.sched.due(T0 + 3600, 2)
        self.assertEqual(report.due_job_ids, ("once",))
        self.assertNotIn("once", self.sched.jobs())
        with self.assertRaises(UnknownJobError):
            self.sched.record("once")

    def test_cancel(self):
        self.sched.schedule("j", parse_cron("* * * * *"), 0)
        record = self.sched.cancel("j", 1)
        self.assertEqual(record.job_id, "j")
        self.assertEqual(self.sched.jobs(), ())
        with self.assertRaises(UnknownJobError):
            self.sched.cancel("j", 2)

    def test_trigger_manual_and_consumes_oneshot(self):
        self.sched.schedule("once", OneShotSpec(T0 + 99999), 0)
        event = self.sched.trigger("once", 1)
        self.assertIsInstance(event, FireEvent)
        self.assertTrue(event.manual)
        self.assertEqual(event.tick, -1)
        self.assertNotIn("once", self.sched.jobs())
        with self.assertRaises(UnknownJobError):
            self.sched.trigger("ghost", 2)

    def test_next_fire_cron(self):
        self.sched.schedule("hourly", parse_cron("0 * * * *"), 0)
        self.assertEqual(self.sched.next_fire("hourly", T0), T0 + 3600)
        with self.assertRaises(UnknownJobError):
            self.sched.next_fire("ghost", T0)

    def test_validation(self):
        with self.assertRaises(SchedulerError):
            self.sched.schedule("", parse_cron("* * * * *"), 0)
        with self.assertRaises(SchedulerError):
            self.sched.schedule("j", parse_cron("* * * * *"), -1)
        with self.assertRaises(SchedulerError):
            self.sched.due(-1, 0)
        with self.assertRaises(SchedulerError):
            self.sched.schedule("j", object(), 0)


class TestAudit(unittest.TestCase):
    def test_audit_shape(self):
        event = job_scheduler_audit_event("scheduled", 7, "j1")
        self.assertEqual(event["kind"], "job-scheduler.scheduled")
        self.assertEqual(event["schema"], SCHEMA)
        self.assertEqual(event["version"], VERSION)
        with self.assertRaises(SchedulerError):
            job_scheduler_audit_event("bogus", 0)


if __name__ == "__main__":
    unittest.main()
