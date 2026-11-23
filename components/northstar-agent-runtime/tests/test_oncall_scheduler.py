"""Tests for oncall_scheduler: rotations, schedules, handoff bookkeeping."""

import unittest
from pathlib import Path

from oncall_scheduler import (
    ONCALL_SCHEDULER_VERSION,
    SCHEMA_PIN,
    BeforeScheduleError,
    DuplicateRotationError,
    HandoffError,
    NoScheduleError,
    OnCallScheduler,
    OnCallSchedulerError,
    UnknownMemberError,
    UnknownRotationError,
    oncall_scheduler_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(ONCALL_SCHEDULER_VERSION, "oncall-scheduler.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.oncall-scheduler.v1")


class TestCreateRotation(unittest.TestCase):
    def setUp(self):
        self.s = OnCallScheduler()

    def test_create_happy_path(self):
        r = self.s.create_rotation("primary", ("alice", "bob"), 0)
        self.assertEqual(r.rotation_id, "primary")
        self.assertEqual(r.members, ("alice", "bob"))
        self.assertTrue(r.digest.startswith("sha256:"))

    def test_create_list_members(self):
        r = self.s.create_rotation("r", ["a", "b", "c"], 1)
        self.assertEqual(r.members, ("a", "b", "c"))

    def test_create_duplicate(self):
        self.s.create_rotation("r", ("a", "b"), 0)
        with self.assertRaises(DuplicateRotationError):
            self.s.create_rotation("r", ("a", "b"), 1)

    def test_create_empty_members(self):
        with self.assertRaises(OnCallSchedulerError):
            self.s.create_rotation("r", (), 0)
        with self.assertRaises(OnCallSchedulerError):
            self.s.create_rotation("r", "ab", 0)

    def test_create_duplicate_members(self):
        with self.assertRaises(OnCallSchedulerError):
            self.s.create_rotation("r", ("a", "a"), 0)

    def test_create_bad_member_types(self):
        with self.assertRaises(OnCallSchedulerError):
            self.s.create_rotation("r", ("a", 1), 0)
        with self.assertRaises(OnCallSchedulerError):
            self.s.create_rotation("r", ("a", ""), 0)

    def test_create_bad_seq(self):
        with self.assertRaises(OnCallSchedulerError):
            self.s.create_rotation("r", ("a", "b"), True)
        with self.assertRaises(OnCallSchedulerError):
            self.s.create_rotation("r", ("a", "b"), -1)
        with self.assertRaises(OnCallSchedulerError):
            self.s.create_rotation("r", ("a", "b"), "0")

    def test_create_bad_id(self):
        with self.assertRaises(OnCallSchedulerError):
            self.s.create_rotation("", ("a", "b"), 0)
        with self.assertRaises(OnCallSchedulerError):
            self.s.create_rotation(5, ("a", "b"), 0)

    def test_digest_determinism(self):
        a = OnCallScheduler()
        b = OnCallScheduler()
        ra = a.create_rotation("r", ("x", "y"), 3)
        rb = b.create_rotation("r", ("x", "y"), 3)
        self.assertEqual(ra.digest, rb.digest)


class TestSchedule(unittest.TestCase):
    def setUp(self):
        self.s = OnCallScheduler()
        self.s.create_rotation("primary", ("alice", "bob", "carol"), 0)

    def test_schedule_happy_path(self):
        r = self.s.schedule("primary", 7, 100, 1)
        self.assertEqual(r.shift_length_seqs, 7)
        self.assertEqual(r.start_seq, 100)

    def test_schedule_unknown_rotation(self):
        with self.assertRaises(UnknownRotationError):
            self.s.schedule("nope", 7, 0, 0)

    def test_schedule_bad_length(self):
        for bad in (0, -1, True, "7", 2.5):
            with self.assertRaises(OnCallSchedulerError):
                self.s.schedule("primary", bad, 0, 0)

    def test_schedule_bad_start(self):
        with self.assertRaises(OnCallSchedulerError):
            self.s.schedule("primary", 7, -5, 0)

    def test_schedule_replaces(self):
        self.s.schedule("primary", 7, 0, 1)
        r2 = self.s.schedule("primary", 14, 50, 2)
        self.assertEqual(self.s.schedule_info("primary").shift_length_seqs, 14)
        self.assertEqual(r2.start_seq, 50)

    def test_schedule_info_unknown(self):
        with self.assertRaises(NoScheduleError):
            self.s.schedule_info("primary")


class TestWhoIsOncall(unittest.TestCase):
    def setUp(self):
        self.s = OnCallScheduler()
        self.s.create_rotation("primary", ("alice", "bob", "carol"), 0)
        self.s.schedule("primary", 10, 0, 1)

    def test_basic_rotation(self):
        self.assertEqual(self.s.who_is_oncall("primary", 0, 0).active_member, "alice")
        self.assertEqual(self.s.who_is_oncall("primary", 9, 0).active_member, "alice")
        self.assertEqual(self.s.who_is_oncall("primary", 10, 0).active_member, "bob")
        self.assertEqual(self.s.who_is_oncall("primary", 25, 0).active_member, "carol")
        self.assertEqual(self.s.who_is_oncall("primary", 30, 0).active_member, "alice")

    def test_shift_fields(self):
        r = self.s.who_is_oncall("primary", 25, 0)
        self.assertEqual(r.shift_index, 2)
        self.assertEqual(r.shift_start, 20)
        self.assertEqual(r.shift_end, 30)
        self.assertEqual(r.scheduled_member, "carol")
        self.assertFalse(r.handoff_applied)

    def test_unknown_rotation(self):
        with self.assertRaises(UnknownRotationError):
            self.s.who_is_oncall("nope", 5, 0)

    def test_no_schedule(self):
        s2 = OnCallScheduler()
        s2.create_rotation("x", ("a",), 0)
        with self.assertRaises(NoScheduleError):
            s2.who_is_oncall("x", 5, 0)

    def test_before_schedule_start(self):
        s2 = OnCallScheduler()
        s2.create_rotation("x", ("a",), 0)
        s2.schedule("x", 10, 50, 1)
        with self.assertRaises(BeforeScheduleError):
            s2.who_is_oncall("x", 49, 0)

    def test_bad_at_seq(self):
        with self.assertRaises(OnCallSchedulerError):
            self.s.who_is_oncall("primary", True, 0)
        with self.assertRaises(OnCallSchedulerError):
            self.s.who_is_oncall("primary", -1, 0)

    def test_digest_determinism(self):
        a = self.s.who_is_oncall("primary", 5, 0)
        b = self.s.who_is_oncall("primary", 5, 0)
        self.assertEqual(a.digest, b.digest)
        c = self.s.who_is_oncall("primary", 6, 0)
        self.assertNotEqual(a.digest, c.digest)


class TestHandoff(unittest.TestCase):
    def setUp(self):
        self.s = OnCallScheduler()
        self.s.create_rotation("primary", ("alice", "bob", "carol"), 0)
        self.s.schedule("primary", 10, 0, 1)

    def test_handoff_happy_path(self):
        h = self.s.handoff("primary", "alice", "bob", 3)
        self.assertEqual(h.from_member, "alice")
        self.assertEqual(h.to_member, "bob")
        self.assertEqual(h.effective_seq, 3)
        r = self.s.who_is_oncall("primary", 5, 0)
        self.assertEqual(r.active_member, "bob")
        self.assertTrue(r.handoff_applied)
        self.assertEqual(r.scheduled_member, "alice")

    def test_handoff_not_yet_effective(self):
        self.s.handoff("primary", "alice", "carol", 5)
        before = self.s.who_is_oncall("primary", 4, 0)
        self.assertEqual(before.active_member, "alice")
        self.assertFalse(before.handoff_applied)
        after = self.s.who_is_oncall("primary", 5, 0)
        self.assertEqual(after.active_member, "carol")

    def test_handoff_expires_at_shift_end(self):
        self.s.handoff("primary", "alice", "bob", 3)
        nxt = self.s.who_is_oncall("primary", 10, 0)
        self.assertEqual(nxt.active_member, "bob")  # scheduled bob for shift 1
        self.assertFalse(nxt.handoff_applied)

    def test_handoff_wrong_from(self):
        with self.assertRaises(HandoffError):
            self.s.handoff("primary", "bob", "carol", 3)

    def test_handoff_to_unknown_member(self):
        with self.assertRaises(UnknownMemberError):
            self.s.handoff("primary", "alice", "zoe", 3)

    def test_handoff_to_self_noop(self):
        with self.assertRaises(HandoffError):
            self.s.handoff("primary", "alice", "alice", 3)

    def test_handoff_after_handoff_must_name_active(self):
        self.s.handoff("primary", "alice", "bob", 3)
        # stale from_member must be refused; the chain continues from bob
        with self.assertRaises(HandoffError):
            self.s.handoff("primary", "alice", "carol", 6)
        h2 = self.s.handoff("primary", "bob", "carol", 6)
        self.assertEqual(h2.from_member, "bob")
        r = self.s.who_is_oncall("primary", 7, 0)
        self.assertEqual(r.active_member, "carol")

    def test_handoff_unknown_rotation(self):
        with self.assertRaises(UnknownRotationError):
            self.s.handoff("nope", "a", "b", 0)

    def test_handoff_no_schedule(self):
        s2 = OnCallScheduler()
        s2.create_rotation("x", ("a", "b"), 0)
        with self.assertRaises(NoScheduleError):
            s2.handoff("x", "a", "b", 0)

    def test_handoff_ledger_view(self):
        h = self.s.handoff("primary", "alice", "bob", 3)
        hs = self.s.handoffs("primary")
        self.assertEqual(len(hs), 1)
        self.assertEqual(hs[0].digest, h.digest)


class TestViews(unittest.TestCase):
    def test_rotations_sorted(self):
        s = OnCallScheduler()
        s.create_rotation("b", ("a",), 0)
        s.create_rotation("a", ("x",), 0)
        self.assertEqual(s.rotations(), ("a", "b"))

    def test_rotation_view_pins_roster(self):
        s = OnCallScheduler()
        s.create_rotation("r", ("x", "y"), 5)
        v = s.rotation("r")
        self.assertEqual(v.members, ("x", "y"))
        with self.assertRaises(UnknownRotationError):
            s.rotation("nope")

    def test_frozen_records(self):
        s = OnCallScheduler()
        s.create_rotation("r", ("a", "b"), 0)
        s.schedule("r", 5, 0, 1)
        with self.assertRaises(AttributeError):
            s.who_is_oncall("r", 1, 0).active_member = "x"  # type: ignore


class TestAudit(unittest.TestCase):
    def test_shapes(self):
        for kind in (
            "rotation-created",
            "rotation-scheduled",
            "oncall-resolved",
            "handoff-recorded",
            "rejected",
        ):
            ev = oncall_scheduler_audit_event(kind, 7, rotation_id="primary")
            self.assertEqual(ev["schema"], "audit.ndjson/1")
            self.assertEqual(ev["module"], "oncall_scheduler")
            self.assertEqual(ev["event"]["kind"], kind)
            self.assertEqual(ev["event"]["seq"], 7)
            self.assertTrue(ev["digest"].startswith("sha256:"))

    def test_bad_kind(self):
        with self.assertRaises(OnCallSchedulerError):
            oncall_scheduler_audit_event("bogus", 0)

    def test_bad_seq(self):
        with self.assertRaises(OnCallSchedulerError):
            oncall_scheduler_audit_event("rejected", -1)


class TestHouse(unittest.TestCase):
    def test_stdlib_only(self):
        src = (Path(__file__).resolve().parent.parent / "oncall_scheduler.py").read_text()
        import ast

        tree = ast.parse(src)
        allowed = {
            "hashlib",
            "threading",
            "dataclasses",
            "typing",
            "__future__",
            "canonical_json",
            "json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)

    def test_main(self):
        import oncall_scheduler

        oncall_scheduler.main()

    def test_concurrency(self):
        import threading as th

        s = OnCallScheduler()
        s.create_rotation("r", ("a", "b", "c"), 0)
        s.schedule("r", 5, 0, 1)
        results = []
        def worker():
            for i in range(20):
                results.append(s.who_is_oncall("r", i % 15, 0).active_member)
        threads = [th.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(results), 100)
        self.assertEqual(results[:5], ["a"] * 5)


if __name__ == "__main__":
    unittest.main()
