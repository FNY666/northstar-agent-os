"""Tests for the alert_manager module."""

from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError

from alert_manager import (
    ACTIVE,
    AUDIT_SCHEMA,
    ALERT_MANAGER_SCHEMA,
    ALERT_MANAGER_VERSION,
    CRITICAL,
    DEFAULT_RECEIVER,
    INFO,
    KIND_FIRED,
    RESOLVED,
    WARNING,
    AlertManager,
    AlertManagerError,
    AlertRecord,
    AlreadyResolvedError,
    ExpiredSilenceError,
    RouteRule,
    RoutedAlert,
    SilenceRecord,
    UnknownAlertError,
    UnknownSilenceError,
    alert_manager_audit_event,
)


def _am() -> AlertManager:
    return AlertManager()


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(ALERT_MANAGER_VERSION, "alert-manager.v1")

    def test_schema_pin(self):
        self.assertEqual(ALERT_MANAGER_SCHEMA, "northstar.alert-manager.v1")

    def test_audit_schema(self):
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")


class TestFire(unittest.TestCase):
    def test_fire_happy_path(self):
        rec = _am().fire("HighLatency", {"service": "api"}, CRITICAL, 1)
        self.assertEqual(rec.name, "HighLatency")
        self.assertEqual(rec.severity, CRITICAL)
        self.assertEqual(rec.status, ACTIVE)
        self.assertEqual(rec.labels, (("service", "api"),))
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertTrue(rec.alert_id.startswith("alert-"))

    def test_fire_digest_deterministic(self):
        a = _am().fire("X", {"a": "b"}, WARNING, 1)
        b = _am().fire("X", {"a": "b"}, WARNING, 1)
        # separate instances, same inputs -> byte-identical digest except alert id counter
        self.assertEqual(a.name, b.name)
        self.assertEqual(a.digest, b.digest)

    def test_fire_dedup_idempotent(self):
        am = _am()
        a = am.fire("X", {"a": "b"}, WARNING, 1)
        again = am.fire("X", {"a": "b"}, WARNING, 5)
        self.assertEqual(a.alert_id, again.alert_id)
        self.assertEqual(len(am.active_alerts()), 1)

    def test_fire_different_labels_new_alert(self):
        am = _am()
        a = am.fire("X", {"a": "b"}, WARNING, 1)
        b = am.fire("X", {"a": "c"}, WARNING, 2)
        self.assertNotEqual(a.alert_id, b.alert_id)

    def test_fire_bad_name(self):
        am = _am()
        with self.assertRaises(AlertManagerError):
            am.fire("", {"a": "b"}, WARNING, 1)
        with self.assertRaises(AlertManagerError):
            am.fire(123, {"a": "b"}, WARNING, 1)

    def test_fire_bad_labels(self):
        am = _am()
        with self.assertRaises(AlertManagerError):
            am.fire("X", "not-a-mapping", WARNING, 1)
        with self.assertRaises(AlertManagerError):
            am.fire("X", {}, WARNING, 1)
        with self.assertRaises(AlertManagerError):
            am.fire("X", {"a": 1}, WARNING, 1)
        with self.assertRaises(AlertManagerError):
            am.fire("X", {"": "b"}, WARNING, 1)

    def test_fire_bad_severity(self):
        with self.assertRaises(AlertManagerError):
            _am().fire("X", {"a": "b"}, "fatal", 1)

    def test_fire_bad_seq(self):
        am = _am()
        with self.assertRaises(AlertManagerError):
            am.fire("X", {"a": "b"}, WARNING, True)
        with self.assertRaises(AlertManagerError):
            am.fire("X", {"a": "b"}, WARNING, -1)
        with self.assertRaises(AlertManagerError):
            am.fire("X", {"a": "b"}, WARNING, "1")

    def test_fire_info_severity(self):
        rec = _am().fire("Deploy", {"a": "b"}, INFO, 1)
        self.assertEqual(rec.severity, INFO)

    def test_fire_annotations(self):
        rec = _am().fire("X", {"a": "b"}, WARNING, 1, annotations={"runbook": "x"})
        self.assertEqual(rec.annotations, (("runbook", "x"),))
        with self.assertRaises(AlertManagerError):
            _am().fire("X", {"a": "b"}, WARNING, 1, annotations={"k": 1})


class TestResolve(unittest.TestCase):
    def test_resolve_happy_path(self):
        am = _am()
        a = am.fire("X", {"a": "b"}, WARNING, 1)
        rec = am.resolve(a.alert_id, 2)
        self.assertEqual(rec.alert_id, a.alert_id)
        self.assertEqual(am.alert(a.alert_id).status, RESOLVED)
        self.assertEqual(am.active_alerts(), ())

    def test_resolve_unknown(self):
        with self.assertRaises(UnknownAlertError):
            _am().resolve("alert-999", 1)

    def test_resolve_twice_refused(self):
        am = _am()
        a = am.fire("X", {"a": "b"}, WARNING, 1)
        am.resolve(a.alert_id, 2)
        with self.assertRaises(AlreadyResolvedError):
            am.resolve(a.alert_id, 3)

    def test_refire_after_resolve_new_id(self):
        am = _am()
        a = am.fire("X", {"a": "b"}, WARNING, 1)
        am.resolve(a.alert_id, 2)
        b = am.fire("X", {"a": "b"}, WARNING, 3)
        self.assertNotEqual(a.alert_id, b.alert_id)
        self.assertEqual(len(am.active_alerts()), 1)


class TestSilence(unittest.TestCase):
    def test_silence_happy_path(self):
        rec = _am().silence({"service": "api"}, 0, 10, 1, comment="deploy")
        self.assertTrue(rec.silence_id.startswith("silence-"))
        self.assertTrue(rec.active)
        self.assertEqual(rec.comment, "deploy")
        self.assertTrue(rec.digest.startswith("sha256:"))

    def test_silence_empty_matchers_refused(self):
        with self.assertRaises(AlertManagerError):
            _am().silence({}, 0, 10, 1)

    def test_silence_bad_window(self):
        with self.assertRaises(AlertManagerError):
            _am().silence({"a": "b"}, 10, 5, 1)

    def test_silence_bad_seqs(self):
        with self.assertRaises(AlertManagerError):
            _am().silence({"a": "b"}, -1, 5, 1)
        with self.assertRaises(AlertManagerError):
            _am().silence({"a": "b"}, 0, 5, True)

    def test_expire_silence(self):
        am = _am()
        s = am.silence({"a": "b"}, 0, 10, 1)
        rec = am.expire_silence(s.silence_id, 2)
        self.assertEqual(rec.silence_id, s.silence_id)
        self.assertFalse(am.silences()[0].active)
        with self.assertRaises(ExpiredSilenceError):
            am.expire_silence(s.silence_id, 3)

    def test_expire_unknown_silence(self):
        with self.assertRaises(UnknownSilenceError):
            _am().expire_silence("silence-999", 1)


class TestRoute(unittest.TestCase):
    def test_route_default_receiver(self):
        am = _am()
        a = am.fire("X", {"a": "b"}, WARNING, 1)
        report = am.route(2)
        self.assertEqual(len(report.routes), 1)
        r = report.routes[0]
        self.assertIsInstance(r, RoutedAlert)
        self.assertEqual(r.alert_id, a.alert_id)
        self.assertEqual(r.receiver, DEFAULT_RECEIVER)
        self.assertFalse(r.silenced)
        self.assertIsNone(r.silence_id)

    def test_route_silenced(self):
        am = _am()
        a = am.fire("X", {"service": "api"}, WARNING, 1)
        s = am.silence({"service": "api"}, 0, 10, 2)
        report = am.route(3)
        by_id = {r.alert_id: r for r in report.routes}
        self.assertTrue(by_id[a.alert_id].silenced)
        self.assertEqual(by_id[a.alert_id].silence_id, s.silence_id)
        # suppression is visible: receiver still assigned
        self.assertEqual(by_id[a.alert_id].receiver, DEFAULT_RECEIVER)

    def test_route_silence_outside_window(self):
        am = _am()
        a = am.fire("X", {"service": "api"}, WARNING, 1)
        am.silence({"service": "api"}, 0, 10, 2)
        report = am.route(99)  # past ends_seq
        by_id = {r.alert_id: r for r in report.routes}
        self.assertFalse(by_id[a.alert_id].silenced)

    def test_route_silence_expired_early(self):
        am = _am()
        a = am.fire("X", {"service": "api"}, WARNING, 1)
        s = am.silence({"service": "api"}, 0, 100, 2)
        am.expire_silence(s.silence_id, 3)
        report = am.route(4)
        by_id = {r.alert_id: r for r in report.routes}
        self.assertFalse(by_id[a.alert_id].silenced)

    def test_route_rule_first_match_wins(self):
        am = _am()
        a = am.fire("X", {"service": "api", "tier": "1"}, WARNING, 1)
        am.add_route_rule({"service": "api"}, "team-a", 2)
        am.add_route_rule({"tier": "1"}, "team-b", 3)
        report = am.route(4)
        by_id = {r.alert_id: r for r in report.routes}
        self.assertEqual(by_id[a.alert_id].receiver, "team-a")

    def test_route_rule_no_match_falls_through(self):
        am = _am()
        a = am.fire("X", {"service": "other"}, WARNING, 1)
        am.add_route_rule({"service": "api"}, "team-a", 2)
        report = am.route(3)
        by_id = {r.alert_id: r for r in report.routes}
        self.assertEqual(by_id[a.alert_id].receiver, DEFAULT_RECEIVER)

    def test_route_skips_resolved(self):
        am = _am()
        a = am.fire("X", {"a": "b"}, WARNING, 1)
        b = am.fire("Y", {"a": "b"}, WARNING, 2)
        am.resolve(a.alert_id, 3)
        report = am.route(4)
        self.assertEqual([r.alert_id for r in report.routes], [b.alert_id])

    def test_route_deterministic_order(self):
        am = _am()
        am.fire("B", {"a": "b"}, WARNING, 1)
        am.fire("A", {"a": "b"}, WARNING, 2)
        r1 = am.route(3)
        r2 = am.route(3)
        self.assertEqual([r.alert_id for r in r1.routes],
                         [r.alert_id for r in r2.routes])
        self.assertEqual(r1.digest, r2.digest)

    def test_add_route_rule_validation(self):
        am = _am()
        with self.assertRaises(AlertManagerError):
            am.add_route_rule({}, "team-a", 1)
        with self.assertRaises(AlertManagerError):
            am.add_route_rule({"a": "b"}, "", 1)
        with self.assertRaises(AlertManagerError):
            am.add_route_rule({"a": 1}, "team-a", 1)
        rule = am.add_route_rule({"a": "b"}, "team-a", 1)
        self.assertIsInstance(rule, RouteRule)
        self.assertEqual(len(am.rules()), 1)

    def test_silence_partial_matcher_no_suppress(self):
        am = _am()
        a = am.fire("X", {"service": "api", "region": "us"}, WARNING, 1)
        # silence requires BOTH labels; alert missing region=eu -> no match
        am.silence({"service": "api", "region": "eu"}, 0, 10, 2)
        report = am.route(3)
        by_id = {r.alert_id: r for r in report.routes}
        self.assertFalse(by_id[a.alert_id].silenced)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        ev = alert_manager_audit_event(KIND_FIRED, 1, alert_id="alert-1")
        self.assertEqual(ev["schema"], AUDIT_SCHEMA)
        self.assertEqual(ev["kind"], KIND_FIRED)
        self.assertEqual(ev["seq"], 1)
        self.assertEqual(ev["detail"]["alert_id"], "alert-1")
        self.assertEqual(ev["module"], "alert_manager")

    def test_audit_unknown_kind(self):
        with self.assertRaises(AlertManagerError):
            alert_manager_audit_event("bogus", 1)

    def test_audit_bad_seq(self):
        with self.assertRaises(AlertManagerError):
            alert_manager_audit_event(KIND_FIRED, -1)


class TestFrozen(unittest.TestCase):
    def test_records_frozen(self):
        rec = _am().fire("X", {"a": "b"}, WARNING, 1)
        with self.assertRaises(FrozenInstanceError):
            rec.status = RESOLVED  # type: ignore[misc]
        s = _am().silence({"a": "b"}, 0, 1, 1)
        with self.assertRaises(FrozenInstanceError):
            s.active = False  # type: ignore[misc]

    def test_record_types(self):
        am = _am()
        a = am.fire("X", {"a": "b"}, WARNING, 1)
        s = am.silence({"a": "b"}, 0, 1, 2)
        self.assertIsInstance(a, AlertRecord)
        self.assertIsInstance(s, SilenceRecord)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        import alert_manager as m

        m.main()  # raises on any broken invariant


if __name__ == "__main__":
    unittest.main()
