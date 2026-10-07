"""Tests for incident_manager (PagerDuty-style lifecycle)."""

import unittest

from incident_manager import (
    ACKNOWLEDGED,
    INCIDENT_MANAGER_SCHEMA,
    INCIDENT_MANAGER_VERSION,
    RESOLVED,
    SEV1,
    SEV2,
    SEV3,
    SEV4,
    SEVERITY_ORDER,
    TRIGGERED,
    IllegalTransitionError,
    IncidentManager,
    NotAnEscalationError,
    TerminalIncidentError,
    UnknownIncidentError,
    incident_manager_audit_event,
)


class TestPinsAndSeverities(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(INCIDENT_MANAGER_VERSION, "incident-manager.v1")
        self.assertEqual(INCIDENT_MANAGER_SCHEMA, "northstar.incident-manager.v1")

    def test_severity_order(self):
        self.assertEqual(SEVERITY_ORDER, (SEV1, SEV2, SEV3, SEV4))
        self.assertLess(SEVERITY_ORDER.index(SEV1), SEVERITY_ORDER.index(SEV4))


class TestCreate(unittest.TestCase):
    def test_create_happy_path(self):
        mgr = IncidentManager()
        rec = mgr.create("db down", SEV1, "payments-db", 1)
        self.assertEqual(rec.incident_id, "inc-1")
        self.assertEqual(rec.state, TRIGGERED)
        self.assertEqual(rec.severity, SEV1)
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(rec.version, INCIDENT_MANAGER_VERSION)
        self.assertEqual(rec.schema, INCIDENT_MANAGER_SCHEMA)

    def test_create_ids_monotonic(self):
        mgr = IncidentManager()
        a = mgr.create("a", SEV4, "svc", 1)
        b = mgr.create("b", SEV4, "svc", 2)
        self.assertEqual((a.incident_id, b.incident_id), ("inc-1", "inc-2"))

    def test_create_digest_deterministic(self):
        m1, m2 = IncidentManager(), IncidentManager()
        r1 = m1.create("same", SEV2, "svc", 1)
        r2 = m2.create("same", SEV2, "svc", 1)
        self.assertEqual(r1.digest, r2.digest)

    def test_create_digest_content_sensitive(self):
        m1, m2 = IncidentManager(), IncidentManager()
        r1 = m1.create("same", SEV2, "svc", 1)
        r2 = m2.create("same", SEV3, "svc", 1)
        self.assertNotEqual(r1.digest, r2.digest)

    def test_create_bad_severity_refused(self):
        mgr = IncidentManager()
        with self.assertRaises(ValueError):
            mgr.create("t", "P0", "svc", 1)

    def test_create_empty_title_refused(self):
        mgr = IncidentManager()
        with self.assertRaises(ValueError):
            mgr.create("", SEV1, "svc", 1)

    def test_create_empty_service_refused(self):
        mgr = IncidentManager()
        with self.assertRaises(ValueError):
            mgr.create("t", SEV1, "", 1)

    def test_create_bool_seq_refused(self):
        mgr = IncidentManager()
        with self.assertRaises(TypeError):
            mgr.create("t", SEV1, "svc", True)

    def test_create_negative_seq_refused(self):
        mgr = IncidentManager()
        with self.assertRaises(ValueError):
            mgr.create("t", SEV1, "svc", -1)


class TestAck(unittest.TestCase):
    def test_ack_happy_path(self):
        mgr = IncidentManager()
        rec = mgr.create("db down", SEV1, "svc", 1)
        ack = mgr.ack(rec.incident_id, "oncall-alice", 2)
        self.assertEqual(ack.responder, "oncall-alice")
        self.assertTrue(ack.digest.startswith("sha256:"))
        self.assertEqual(mgr.incident(rec.incident_id).state, ACKNOWLEDGED)

    def test_ack_records_responder(self):
        mgr = IncidentManager()
        rec = mgr.create("db down", SEV1, "svc", 1)
        mgr.ack(rec.incident_id, "bob", 2)
        self.assertEqual(mgr.incident(rec.incident_id).acknowledged_by, "bob")

    def test_ack_unknown_id_refused(self):
        mgr = IncidentManager()
        with self.assertRaises(UnknownIncidentError):
            mgr.ack("inc-999", "bob", 1)

    def test_ack_twice_refused(self):
        mgr = IncidentManager()
        rec = mgr.create("t", SEV2, "svc", 1)
        mgr.ack(rec.incident_id, "bob", 2)
        with self.assertRaises(IllegalTransitionError):
            mgr.ack(rec.incident_id, "carol", 3)

    def test_ack_resolved_refused(self):
        mgr = IncidentManager()
        rec = mgr.create("t", SEV2, "svc", 1)
        mgr.resolve(rec.incident_id, "fixed", 2)
        with self.assertRaises(TerminalIncidentError):
            mgr.ack(rec.incident_id, "bob", 3)

    def test_ack_seq_rewind_refused(self):
        mgr = IncidentManager()
        rec = mgr.create("t", SEV2, "svc", 5)
        with self.assertRaises(ValueError):
            mgr.ack(rec.incident_id, "bob", 5)


class TestEscalate(unittest.TestCase):
    def test_escalate_happy_path(self):
        mgr = IncidentManager()
        rec = mgr.create("slow", SEV4, "svc", 1)
        esc = mgr.escalate(rec.incident_id, SEV2, "widening", 2)
        self.assertEqual(esc.from_severity, SEV4)
        self.assertEqual(esc.to_severity, SEV2)
        self.assertEqual(mgr.incident(rec.incident_id).severity, SEV2)

    def test_escalate_history_kept(self):
        mgr = IncidentManager()
        rec = mgr.create("slow", SEV4, "svc", 1)
        mgr.escalate(rec.incident_id, SEV3, "r1", 2)
        mgr.escalate(rec.incident_id, SEV1, "r2", 3)
        self.assertEqual(
            mgr.incident(rec.incident_id).severity_history, (SEV4, SEV3, SEV1)
        )

    def test_escalate_from_acknowledged_ok(self):
        mgr = IncidentManager()
        rec = mgr.create("t", SEV3, "svc", 1)
        mgr.ack(rec.incident_id, "bob", 2)
        mgr.escalate(rec.incident_id, SEV1, "bad", 3)
        self.assertEqual(mgr.incident(rec.incident_id).severity, SEV1)

    def test_escalate_same_severity_refused(self):
        mgr = IncidentManager()
        rec = mgr.create("t", SEV2, "svc", 1)
        with self.assertRaises(NotAnEscalationError):
            mgr.escalate(rec.incident_id, SEV2, "no-op", 2)

    def test_escalate_downgrade_refused(self):
        mgr = IncidentManager()
        rec = mgr.create("t", SEV1, "svc", 1)
        with self.assertRaises(NotAnEscalationError):
            mgr.escalate(rec.incident_id, SEV4, "calmer", 2)

    def test_escalate_resolved_refused(self):
        mgr = IncidentManager()
        rec = mgr.create("t", SEV2, "svc", 1)
        mgr.resolve(rec.incident_id, "done", 2)
        with self.assertRaises(TerminalIncidentError):
            mgr.escalate(rec.incident_id, SEV1, "late", 3)

    def test_escalate_unknown_severity_refused(self):
        mgr = IncidentManager()
        rec = mgr.create("t", SEV2, "svc", 1)
        with self.assertRaises(ValueError):
            mgr.escalate(rec.incident_id, "P0", "x", 2)


class TestResolve(unittest.TestCase):
    def test_resolve_happy_path(self):
        mgr = IncidentManager()
        rec = mgr.create("t", SEV1, "svc", 1)
        res = mgr.resolve(rec.incident_id, "failover done", 2)
        self.assertEqual(res.note, "failover done")
        self.assertEqual(mgr.incident(rec.incident_id).state, RESOLVED)

    def test_resolve_unacked_ok(self):
        mgr = IncidentManager()
        rec = mgr.create("t", SEV3, "svc", 1)
        mgr.resolve(rec.incident_id, "self-healed", 2)
        self.assertEqual(mgr.incident(rec.incident_id).resolved_note, "self-healed")

    def test_resolve_twice_refused(self):
        mgr = IncidentManager()
        rec = mgr.create("t", SEV2, "svc", 1)
        mgr.resolve(rec.incident_id, "done", 2)
        with self.assertRaises(TerminalIncidentError):
            mgr.resolve(rec.incident_id, "again", 3)

    def test_full_lifecycle(self):
        mgr = IncidentManager()
        rec = mgr.create("outage", SEV1, "api", 1)
        mgr.ack(rec.incident_id, "alice", 2)
        mgr.resolve(rec.incident_id, "mitigated", 3)
        view = mgr.incident(rec.incident_id)
        self.assertEqual(view.state, RESOLVED)
        self.assertEqual(view.acknowledged_by, "alice")
        self.assertEqual(view.last_seq, 3)


class TestViews(unittest.TestCase):
    def test_incident_view_shape(self):
        mgr = IncidentManager()
        rec = mgr.create("t", SEV2, "svc", 1)
        view = mgr.incident(rec.incident_id)
        d = view.as_dict()
        self.assertEqual(d["incident_id"], "inc-1")
        self.assertEqual(d["severity_history"], ["SEV2"])
        self.assertIsNone(d["acknowledged_by"])
        self.assertEqual(d["schema"], INCIDENT_MANAGER_SCHEMA)

    def test_incidents_filter_by_state(self):
        mgr = IncidentManager()
        a = mgr.create("a", SEV2, "svc", 1)
        b = mgr.create("b", SEV2, "svc", 2)
        mgr.resolve(a.incident_id, "done", 3)
        resolved = mgr.incidents(state=RESOLVED)
        triggered = mgr.incidents(state=TRIGGERED)
        self.assertEqual([v.incident_id for v in resolved], ["inc-1"])
        self.assertEqual([v.incident_id for v in triggered], ["inc-2"])
        self.assertEqual(len(mgr.incidents()), 2)

    def test_incidents_bad_state_refused(self):
        mgr = IncidentManager()
        with self.assertRaises(ValueError):
            mgr.incidents(state="OPEN")

    def test_incident_unknown_id_refused(self):
        mgr = IncidentManager()
        with self.assertRaises(UnknownIncidentError):
            mgr.incident("inc-1")


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        for kind in ("created", "acknowledged", "escalated", "resolved", "rejected"):
            ev = incident_manager_audit_event(kind, 1, incident_id="inc-1", detail="d")
            self.assertEqual(ev["kind"], kind)
            self.assertEqual(ev["seq"], 1)
            self.assertEqual(ev["schema"], INCIDENT_MANAGER_SCHEMA)

    def test_audit_minimal(self):
        ev = incident_manager_audit_event("created", 1)
        self.assertNotIn("incident_id", ev)

    def test_audit_unknown_kind_refused(self):
        with self.assertRaises(ValueError):
            incident_manager_audit_event("paged", 1)

    def test_audit_bad_seq_refused(self):
        with self.assertRaises(TypeError):
            incident_manager_audit_event("created", True)


if __name__ == "__main__":
    unittest.main()
