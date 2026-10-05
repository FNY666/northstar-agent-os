"""Tests for incident_receipts.py (one-hundred-thirteenth batch)."""

import unittest

from incident_receipts import (
    INCIDENT_CLOCK_MISSED_EVENT,
    INCIDENT_DUPLICATE_EVENT,
    INCIDENT_FILED_EVENT,
    INCIDENT_RETENTION_FLOOR_DAYS,
    INCIDENT_RETENTION_REFUSED_EVENT,
    IncidentReceiptError,
    IncidentRegistry,
    incident_audit_event,
    reporting_clock_days,
)

T0 = 1_700_000_000
DAY = 86_400
DIGEST = "ab" * 32


def _file(reg, incident_id="inc-1", **over):
    kw = dict(
        incident_id=incident_id,
        system_id="agent-7",
        severity="serious",
        detected_at=T0,
        reported_at=T0 + DAY,
        summary_digest=DIGEST,
        now=T0 + DAY,
    )
    kw.update(over)
    return reg.file_incident(**kw)


class ReportingClockTests(unittest.TestCase):
    def test_serious_base_clock(self):
        self.assertEqual(reporting_clock_days("serious"), 15)

    def test_serious_death_linked(self):
        self.assertEqual(reporting_clock_days("serious", death_linked=True), 10)

    def test_serious_widespread(self):
        self.assertEqual(reporting_clock_days("serious", widespread=True), 2)

    def test_widespread_beats_death_linked(self):
        self.assertEqual(
            reporting_clock_days("serious", death_linked=True, widespread=True), 2
        )

    def test_critical_fastest(self):
        self.assertEqual(reporting_clock_days("critical"), 2)

    def test_systemic_tiers(self):
        self.assertEqual(
            [reporting_clock_days("systemic_risk", systemic_tier=t) for t in (1, 2, 3, 4)],
            [2, 5, 10, 15],
        )

    def test_systemic_missing_tier_raises(self):
        with self.assertRaises(IncidentReceiptError):
            reporting_clock_days("systemic_risk")

    def test_limited_no_clock(self):
        self.assertIsNone(reporting_clock_days("limited"))

    def test_unknown_severity_raises(self):
        with self.assertRaises(IncidentReceiptError):
            reporting_clock_days("bogus")


class FilingTests(unittest.TestCase):
    def test_on_time_filing_allowed(self):
        reg = IncidentRegistry()
        v = _file(reg, reported_at=T0 + 14 * DAY, now=T0 + 14 * DAY)
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, "incident-filed")
        self.assertIsNotNone(v.receipt)

    def test_exact_deadline_allowed(self):
        reg = IncidentRegistry()
        v = _file(reg, reported_at=T0 + 15 * DAY, now=T0 + 15 * DAY)
        self.assertTrue(v.allowed)

    def test_late_filing_denied_and_escalated(self):
        reg = IncidentRegistry()
        v = _file(reg, reported_at=T0 + 16 * DAY, now=T0 + 16 * DAY)
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, "clock-missed")
        self.assertEqual(v.escalated_to, "critical")
        self.assertEqual(v.days_late, 1)
        self.assertTrue(v.receipt.clock_missed)

    def test_death_linked_clock(self):
        reg = IncidentRegistry()
        v = _file(reg, death_linked=True, reported_at=T0 + 11 * DAY, now=T0 + 11 * DAY)
        self.assertFalse(v.allowed)
        self.assertEqual(v.escalated_to, "critical")

    def test_systemic_tier_clock(self):
        reg = IncidentRegistry()
        v = _file(
            reg,
            severity="systemic_risk",
            systemic_tier=1,
            reported_at=T0 + 3 * DAY,
            now=T0 + 3 * DAY,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.escalated_to, "systemic_risk")
        reg2 = IncidentRegistry()
        v2 = _file(
            reg2,
            incident_id="inc-9",
            severity="systemic_risk",
            systemic_tier=4,
            reported_at=T0 + 14 * DAY,
            now=T0 + 14 * DAY,
        )
        self.assertTrue(v2.allowed)

    def test_limited_never_misses(self):
        reg = IncidentRegistry()
        v = _file(
            reg,
            severity="limited",
            reported_at=T0 + 400 * DAY,
            now=T0 + 400 * DAY,
        )
        self.assertTrue(v.allowed)

    def test_duplicate_idempotent_deny(self):
        reg = IncidentRegistry()
        v1 = _file(reg)
        self.assertTrue(v1.allowed)
        v2 = _file(reg)
        self.assertFalse(v2.allowed)
        self.assertEqual(v2.classification, "duplicate-filing")
        self.assertEqual(len(reg._by_id), 1)

    def test_future_detected_at_rejected(self):
        reg = IncidentRegistry()
        with self.assertRaises(IncidentReceiptError):
            _file(reg, detected_at=T0 + DAY, reported_at=T0 + DAY, now=T0)

    def test_reported_before_detected_rejected(self):
        reg = IncidentRegistry()
        with self.assertRaises(IncidentReceiptError):
            _file(reg, detected_at=T0 + DAY, reported_at=T0, now=T0 + DAY)

    def test_future_reported_at_rejected(self):
        reg = IncidentRegistry()
        with self.assertRaises(IncidentReceiptError):
            _file(reg, detected_at=T0, reported_at=T0 + 2 * DAY, now=T0 + DAY)

    def test_bad_digest_rejected(self):
        reg = IncidentRegistry()
        with self.assertRaises(IncidentReceiptError):
            _file(reg, summary_digest="not-a-digest")

    def test_unknown_severity_rejected(self):
        reg = IncidentRegistry()
        with self.assertRaises(IncidentReceiptError):
            _file(reg, severity="catastrophic")

    def test_chain_intact_and_tamper(self):
        reg = IncidentRegistry()
        _file(reg)
        _file(reg, incident_id="inc-2", detected_at=T0 + DAY,
              reported_at=T0 + 2 * DAY, now=T0 + 2 * DAY)
        ok, _ = reg.verify_chain()
        self.assertTrue(ok)
        # tamper: same digest, altered field
        old = reg.get("inc-2")
        import dataclasses
        reg._by_id["inc-2"] = dataclasses.replace(old, severity="critical")
        ok, reason = reg.verify_chain()
        self.assertFalse(ok)
        self.assertIn("tampered", reason)

    def test_audit_events(self):
        reg = IncidentRegistry()
        v = _file(reg)
        self.assertEqual(
            incident_audit_event(v, incident_id="inc-1", system_id="agent-7")["event"],
            INCIDENT_FILED_EVENT,
        )
        v2 = _file(reg, incident_id="inc-2", reported_at=T0 + 30 * DAY,
                   now=T0 + 30 * DAY)
        ev = incident_audit_event(v2, incident_id="inc-2")
        self.assertEqual(ev["event"], INCIDENT_CLOCK_MISSED_EVENT)
        self.assertEqual(ev["escalated_to"], "critical")
        v3 = _file(reg, incident_id="inc-1")
        self.assertEqual(
            incident_audit_event(v3, incident_id="inc-1")["event"],
            INCIDENT_DUPLICATE_EVENT,
        )


class RetentionTests(unittest.TestCase):
    def test_floor_value(self):
        self.assertEqual(INCIDENT_RETENTION_FLOOR_DAYS, 1825)

    def test_floor_met(self):
        reg = IncidentRegistry()
        v = reg.register_retention(system_id="agent-7", retention_days=1825)
        self.assertTrue(v.allowed)
        self.assertEqual(reg.retention_for("agent-7"), 1825)

    def test_below_floor_refused(self):
        reg = IncidentRegistry()
        v = reg.register_retention(system_id="agent-7", retention_days=1824)
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, "retention-refused")
        self.assertIsNone(reg.retention_for("agent-7"))
        ev = incident_audit_event(v, system_id="agent-7")
        self.assertEqual(ev["event"], INCIDENT_RETENTION_REFUSED_EVENT)

    def test_bad_system_id_rejected(self):
        reg = IncidentRegistry()
        with self.assertRaises(IncidentReceiptError):
            reg.register_retention(system_id="  ", retention_days=2000)


if __name__ == "__main__":
    unittest.main()
