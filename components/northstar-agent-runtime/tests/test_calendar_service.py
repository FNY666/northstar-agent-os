"""Tests for calendar_service."""

import ast
import unittest
from pathlib import Path

from calendar_service import (
    CALENDAR_SERVICE_VERSION,
    SCHEMA_PIN,
    BadInputError,
    BadRRuleError,
    BadRSVPError,
    BadTimeRangeError,
    CalendarService,
    DuplicateCalendarError,
    DuplicateEventError,
    EventCancelledError,
    OverlapError,
    SeqOrderError,
    UnknownAttendeeError,
    UnknownCalendarError,
    UnknownEventError,
    calendar_service_audit_event,
    main,
)


def _svc():
    svc = CalendarService()
    cal = svc.create_calendar("alice", "work", 1)
    return svc, cal.calendar_id


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(CALENDAR_SERVICE_VERSION, "calendar-service.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.calendar-service.v1")


class TestCalendars(unittest.TestCase):
    def test_create_calendar_roundtrip(self):
        svc = CalendarService()
        rec = svc.create_calendar("alice", "work", 1)
        self.assertTrue(rec.calendar_id.startswith("cal-"))
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(svc.calendar(rec.calendar_id), rec)

    def test_duplicate_calendar_refused(self):
        svc = CalendarService()
        svc.create_calendar("alice", "work", 1, calendar_id="cal-x")
        with self.assertRaises(DuplicateCalendarError):
            svc.create_calendar("alice", "work", 2, calendar_id="cal-x")

    def test_unknown_calendar(self):
        svc = CalendarService()
        with self.assertRaises(UnknownCalendarError):
            svc.calendar("cal-nope")

    def test_bad_inputs(self):
        svc = CalendarService()
        with self.assertRaises(BadInputError):
            svc.create_calendar("", "work", 1)
        with self.assertRaises(BadInputError):
            svc.create_calendar("alice", "  ", 1)
        with self.assertRaises(SeqOrderError):
            svc.create_calendar("alice", "work", -1)


class TestEvents(unittest.TestCase):
    def test_create_roundtrip(self):
        svc, cid = _svc()
        ev = svc.create(cid, "standup", 100, 130, 2, attendees=("bob",))
        self.assertTrue(ev.event_id.startswith("ev-"))
        self.assertTrue(ev.uid.startswith("sha256:"))
        self.assertEqual(ev.state, "active")
        self.assertEqual(svc.event(ev.event_id), ev)

    def test_bad_time_range(self):
        svc, cid = _svc()
        with self.assertRaises(BadTimeRangeError):
            svc.create(cid, "x", 130, 100, 2)
        with self.assertRaises(BadTimeRangeError):
            svc.create(cid, "x", 100, 100, 2)
        with self.assertRaises(BadTimeRangeError):
            svc.create(cid, "x", -1, 10, 2)
        with self.assertRaises(BadTimeRangeError):
            svc.create(cid, "x", True, 10, 2)

    def test_unknown_calendar_on_create(self):
        svc = CalendarService()
        with self.assertRaises(UnknownCalendarError):
            svc.create("cal-nope", "x", 1, 2, 1)

    def test_duplicate_event_id(self):
        svc, cid = _svc()
        svc.create(cid, "a", 1, 2, 2, event_id="ev-x")
        with self.assertRaises(DuplicateEventError):
            svc.create(cid, "b", 5, 6, 3, event_id="ev-x")

    def test_overlap_refused_by_default(self):
        svc, cid = _svc()
        svc.create(cid, "a", 100, 200, 2)
        with self.assertRaises(OverlapError):
            svc.create(cid, "b", 150, 250, 3)

    def test_overlap_allowed_opt_in(self):
        svc, cid = _svc()
        svc.create(cid, "a", 100, 200, 2)
        ev = svc.create(cid, "b", 150, 250, 3, allow_overlap=True)
        self.assertEqual(ev.title, "b")

    def test_transparent_events_do_not_conflict(self):
        svc, cid = _svc()
        svc.create(cid, "focus", 100, 200, 2, transparency="transparent")
        ev = svc.create(cid, "meeting", 150, 160, 3)
        self.assertEqual(ev.state, "active")

    def test_touching_edges_do_not_overlap(self):
        svc, cid = _svc()
        svc.create(cid, "a", 100, 200, 2)
        ev = svc.create(cid, "b", 200, 300, 3)
        self.assertEqual(ev.start_seq, 200)

    def test_duplicate_attendees_refused(self):
        svc, cid = _svc()
        with self.assertRaises(BadInputError):
            svc.create(cid, "x", 1, 2, 2, attendees=("bob", "bob"))

    def test_digest_deterministic(self):
        svc, cid = _svc()
        e1 = svc.create(cid, "x", 10, 20, 2, event_id="ev-d")
        svc2 = CalendarService()
        cal2 = svc2.create_calendar("alice", "work", 1, calendar_id=cid)
        self.assertEqual(cal2.calendar_id, cid)
        e2 = svc2.create(cid, "x", 10, 20, 2, event_id="ev-d")
        self.assertEqual(e1.digest, e2.digest)
        self.assertEqual(e1.uid, e2.uid)


class TestRecurrence(unittest.TestCase):
    def test_daily_expansion_in_freebusy(self):
        svc, cid = _svc()
        svc.create(cid, "daily", 100, 110, 2, rrule="FREQ=DAILY;COUNT=3")
        fb = svc.freebusy((cid,), 0, 500, 3)
        self.assertEqual(len(fb.busy), 3)
        self.assertEqual([b.start_seq for b in fb.busy], [100, 101, 102])

    def test_weekly_expansion(self):
        svc, cid = _svc()
        svc.create(cid, "weekly", 10, 12, 2, rrule="FREQ=WEEKLY;COUNT=2")
        fb = svc.freebusy((cid,), 0, 100, 3)
        self.assertEqual([b.start_seq for b in fb.busy], [10, 17])

    def test_bad_rrule_refused(self):
        svc, cid = _svc()
        with self.assertRaises(BadRRuleError):
            svc.create(cid, "x", 1, 2, 2, rrule="FREQ=HOURLY;COUNT=3")
        with self.assertRaises(BadRRuleError):
            svc.create(cid, "x", 1, 2, 2, rrule="FREQ=DAILY")
        with self.assertRaises(BadRRuleError):
            svc.create(cid, "x", 1, 2, 2, rrule="FREQ=DAILY;COUNT=3;UNTIL=99")
        with self.assertRaises(BadRRuleError):
            svc.create(cid, "x", 1, 2, 2, rrule="FREQ=DAILY;COUNT=400")

    def test_recurrence_overlap_refused(self):
        svc, cid = _svc()
        svc.create(cid, "daily", 100, 110, 2, rrule="FREQ=DAILY;COUNT=5")
        with self.assertRaises(OverlapError):
            svc.create(cid, "clash", 102, 103, 3)


class TestFreebusy(unittest.TestCase):
    def test_free_window(self):
        svc, cid = _svc()
        fb = svc.freebusy((cid,), 0, 50, 2)
        self.assertTrue(fb.is_free())
        self.assertTrue(fb.digest.startswith("sha256:"))

    def test_busy_window_clipped(self):
        svc, cid = _svc()
        svc.create(cid, "a", 100, 200, 2)
        fb = svc.freebusy((cid,), 150, 250, 3)
        self.assertFalse(fb.is_free())
        self.assertEqual(len(fb.busy), 1)
        self.assertEqual((fb.busy[0].start_seq, fb.busy[0].end_seq), (150, 200))

    def test_cancelled_invisible(self):
        svc, cid = _svc()
        ev = svc.create(cid, "a", 100, 200, 2)
        svc.cancel(ev.event_id, 3)
        fb = svc.freebusy((cid,), 0, 500, 4)
        self.assertTrue(fb.is_free())

    def test_multi_calendar(self):
        svc = CalendarService()
        c1 = svc.create_calendar("a", "one", 1)
        c2 = svc.create_calendar("b", "two", 2)
        svc.create(c1.calendar_id, "a", 10, 20, 3)
        fb = svc.freebusy((c1.calendar_id, c2.calendar_id), 0, 100, 4)
        self.assertEqual(len(fb.busy), 1)

    def test_bad_window(self):
        svc, cid = _svc()
        with self.assertRaises(BadTimeRangeError):
            svc.freebusy((cid,), 50, 50, 2)
        with self.assertRaises(BadInputError):
            svc.freebusy((), 0, 50, 2)
        with self.assertRaises(UnknownCalendarError):
            svc.freebusy(("cal-nope",), 0, 50, 2)


class TestCancelUpdate(unittest.TestCase):
    def test_cancel_terminal(self):
        svc, cid = _svc()
        ev = svc.create(cid, "a", 100, 200, 2)
        cancelled = svc.cancel(ev.event_id, 3)
        self.assertEqual(cancelled.state, "cancelled")
        self.assertNotEqual(cancelled.digest, ev.digest)
        with self.assertRaises(EventCancelledError):
            svc.cancel(ev.event_id, 4)

    def test_update_roundtrip(self):
        svc, cid = _svc()
        ev = svc.create(cid, "a", 100, 200, 2)
        upd = svc.update(ev.event_id, 3, title="b", location="room 1")
        self.assertEqual(upd.title, "b")
        self.assertEqual(upd.location, "room 1")
        self.assertEqual(upd.uid, ev.uid)  # uid is stable

    def test_update_overlap_refused(self):
        svc, cid = _svc()
        svc.create(cid, "a", 100, 200, 2)
        ev = svc.create(cid, "b", 300, 400, 3)
        with self.assertRaises(OverlapError):
            svc.update(ev.event_id, 4, start_seq=150, end_seq=160)

    def test_update_cancelled_refused(self):
        svc, cid = _svc()
        ev = svc.create(cid, "a", 100, 200, 2)
        svc.cancel(ev.event_id, 3)
        with self.assertRaises(EventCancelledError):
            svc.update(ev.event_id, 4, title="nope")

    def test_unknown_event(self):
        svc, _ = _svc()
        with self.assertRaises(UnknownEventError):
            svc.event("ev-nope")
        with self.assertRaises(UnknownEventError):
            svc.cancel("ev-nope", 2)


class TestRSVP(unittest.TestCase):
    def test_rsvp_roundtrip(self):
        svc, cid = _svc()
        ev = svc.create(cid, "m", 100, 200, 2, attendees=("bob", "carol"))
        rec = svc.rsvp(ev.event_id, "bob", "accepted", 3)
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(svc.rsvps(ev.event_id), {"bob": "accepted"})

    def test_rsvp_moves_forward(self):
        svc, cid = _svc()
        ev = svc.create(cid, "m", 100, 200, 2, attendees=("bob",))
        svc.rsvp(ev.event_id, "bob", "tentative", 3)
        svc.rsvp(ev.event_id, "bob", "accepted", 4)
        self.assertEqual(svc.rsvps(ev.event_id)["bob"], "accepted")

    def test_unknown_attendee_refused(self):
        svc, cid = _svc()
        ev = svc.create(cid, "m", 100, 200, 2, attendees=("bob",))
        with self.assertRaises(UnknownAttendeeError):
            svc.rsvp(ev.event_id, "mallory", "accepted", 3)

    def test_bad_status_refused(self):
        svc, cid = _svc()
        ev = svc.create(cid, "m", 100, 200, 2, attendees=("bob",))
        with self.assertRaises(BadRSVPError):
            svc.rsvp(ev.event_id, "bob", "maybe", 3)

    def test_rsvp_on_cancelled_refused(self):
        svc, cid = _svc()
        ev = svc.create(cid, "m", 100, 200, 2, attendees=("bob",))
        svc.cancel(ev.event_id, 3)
        with self.assertRaises(EventCancelledError):
            svc.rsvp(ev.event_id, "bob", "accepted", 4)


class TestSeqOrder(unittest.TestCase):
    def test_rewind_refused(self):
        svc, cid = _svc()
        with self.assertRaises(SeqOrderError):
            svc.create(cid, "x", 1, 2, 1)  # seq 1 already used
        with self.assertRaises(SeqOrderError):
            svc.create(cid, "x", 1, 2, True)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        ev = calendar_service_audit_event("event-created", 1, {"event_id": "ev-1"})
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["module"], "calendar-service")
        self.assertEqual(ev["kind"], "event-created")
        with self.assertRaises(BadInputError):
            calendar_service_audit_event("nope", 1)

    def test_service_audit_trail(self):
        svc, cid = _svc()
        ev = svc.create(cid, "x", 1, 2, 2)
        kinds = [e.kind for e in svc.audit_log()]
        self.assertIn("calendar-created", kinds)
        self.assertIn("event-created", kinds)


class TestStdlibOnly(unittest.TestCase):
    def test_no_third_party_imports(self):
        src = Path(__file__).resolve().parent.parent.joinpath("calendar_service.py").read_text()
        tree = ast.parse(src)
        allowed = {
            "hashlib",
            "re",
            "threading",
            "dataclasses",
            "typing",
            "json",
            "__future__",
            "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed, alias.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(node.module.split(".")[0], allowed, node.module)


class TestMain(unittest.TestCase):
    def test_main(self):
        main()


if __name__ == "__main__":
    unittest.main()
