"""Tests for quantum_timeline (one-hundred-second batch)."""

import sys
import unittest

sys.path.insert(0, ".")

from quantum_timeline import (  # noqa: E402
    BSI_ASYMMETRIC_PHASEOUT,
    BSI_SIGNATURE_PHASEOUT,
    POSTURE_ACCEPTABLE,
    POSTURE_MIGRATE_BY_2031,
    POSTURE_REVIEW_2035,
    QUANTUM_TIMELINE_DENIED_EVENT,
    QUANTUM_TIMELINE_WARNING_EVENT,
    gate_signing,
    hybrid_sign,
    migration_plan,
    parse_date,
    threat_assessment,
    timeline_denied_event,
    timeline_warning_event,
)


class ParseDateTests(unittest.TestCase):
    def test_iso_date(self):
        d = parse_date("2032-01-15")
        self.assertIsNotNone(d)
        self.assertEqual(d.isoformat(), "2032-01-15")

    def test_iso_datetime(self):
        d = parse_date("2032-01-15T10:00:00")
        self.assertIsNotNone(d)
        self.assertEqual(d.isoformat(), "2032-01-15")

    def test_epoch(self):
        d = parse_date(0)
        self.assertIsNotNone(d)
        self.assertEqual(d.isoformat(), "1970-01-01")

    def test_malformed(self):
        for bad in ("not-a-date", "", "2032-13-99", None, True, object()):
            self.assertIsNone(parse_date(bad), f"expected None for {bad!r}")


class ThreatAssessmentTests(unittest.TestCase):
    def test_postures(self):
        a = threat_assessment("2026-10-04")
        self.assertEqual(a["primitives"]["Ed25519"], POSTURE_MIGRATE_BY_2031)
        self.assertEqual(a["primitives"]["SHA-256"], POSTURE_REVIEW_2035)
        self.assertEqual(a["primitives"]["HMAC-SHA256"], POSTURE_ACCEPTABLE)
        self.assertEqual(a["overall"], POSTURE_MIGRATE_BY_2031)
        self.assertEqual(a["bsi_asymmetric_phaseout"], BSI_ASYMMETRIC_PHASEOUT)
        self.assertEqual(a["bsi_signature_phaseout"], BSI_SIGNATURE_PHASEOUT)

    def test_malformed_date_fails_closed(self):
        a = threat_assessment("garbage")
        self.assertIn("error", a)
        self.assertIsNone(a["as_of"])

    def test_deterministic(self):
        self.assertEqual(
            threat_assessment("2030-06-01"), threat_assessment("2030-06-01")
        )


class GateSigningTests(unittest.TestCase):
    def test_long_lived_ed25519_denied(self):
        v = gate_signing(
            primitive="Ed25519",
            expires_at="2032-06-01",
            credential_kind="passport",
        )
        self.assertEqual(v["verdict"], "deny")
        self.assertIn("2031", v["reason"])
        ev = v["event"]
        self.assertEqual(ev["event"], QUANTUM_TIMELINE_DENIED_EVENT)
        self.assertEqual(ev["reason"], "long-lived-asymmetric-credential")
        self.assertEqual(ev["credential_kind"], "passport")

    def test_boundary_2031_12_31_allowed_with_warning(self):
        v = gate_signing(primitive="Ed25519", expires_at="2031-12-31")
        self.assertEqual(v["verdict"], "allow-with-warning")
        self.assertEqual(v["event"]["event"], QUANTUM_TIMELINE_WARNING_EVENT)

    def test_day_after_boundary_denied(self):
        v = gate_signing(primitive="Ed25519", expires_at="2032-01-01")
        self.assertEqual(v["verdict"], "deny")

    def test_short_lived_token_allowed_with_warning(self):
        v = gate_signing(
            primitive="ed25519",  # alias spelling
            expires_at="2026-10-05",
            credential_kind="session-token",
        )
        self.assertEqual(v["verdict"], "allow-with-warning")
        self.assertEqual(v["event"]["event"], QUANTUM_TIMELINE_WARNING_EVENT)

    def test_sha256_hash_only_unaffected(self):
        v = gate_signing(primitive="SHA-256", expires_at="2040-01-01")
        self.assertEqual(v["verdict"], "allow")
        self.assertIsNone(v["event"])

    def test_hmac_unaffected(self):
        v = gate_signing(primitive="HMAC-SHA256", expires_at="2099-01-01")
        self.assertEqual(v["verdict"], "allow")
        self.assertIsNone(v["event"])

    def test_unknown_primitive_denied(self):
        v = gate_signing(primitive="RSA-2048", expires_at="2027-01-01")
        self.assertEqual(v["verdict"], "deny")
        self.assertIn("unknown primitive", v["reason"])
        self.assertEqual(v["event"]["reason"], "unknown-primitive")

    def test_malformed_expiry_denied(self):
        v = gate_signing(primitive="Ed25519", expires_at="someday")
        self.assertEqual(v["verdict"], "deny")
        self.assertEqual(v["event"]["reason"], "malformed-expiry")

    def test_missing_expiry_denied(self):
        v = gate_signing(primitive="Ed25519", expires_at=None)
        self.assertEqual(v["verdict"], "deny")

    def test_malformed_issued_at_denied(self):
        v = gate_signing(
            primitive="Ed25519",
            expires_at="2027-01-01",
            issued_at="yesterday-ish",
        )
        self.assertEqual(v["verdict"], "deny")
        self.assertEqual(v["event"]["reason"], "malformed-issued-at")

    def test_non_string_primitive_denied(self):
        v = gate_signing(primitive=123, expires_at="2027-01-01")
        self.assertEqual(v["verdict"], "deny")

    def test_epoch_expiry(self):
        # 1893456000 == 2030-01-01: inside the window -> warning.
        v = gate_signing(primitive="Ed25519", expires_at=1893456000)
        self.assertEqual(v["verdict"], "allow-with-warning")


class MigrationPlanTests(unittest.TestCase):
    def test_completeness(self):
        plan = migration_plan()
        modules = {row["module"] for row in plan}
        for expected in (
            "passport",
            "offline_bundle",
            "agent_identity",
            "delegation_credentials",
            "multisig",
            "audit_chain",
            "audit_scitt",
        ):
            self.assertIn(expected, modules, f"missing module {expected}")

    def test_deadlines(self):
        plan = migration_plan()
        by_module = {}
        for row in plan:
            by_module.setdefault(row["module"], []).append(row)
        # Short-lived credential minting follows the 2031 phaseout.
        for row in by_module["passport"]:
            if row["primitive"] == "Ed25519":
                self.assertEqual(row["deadline"], "2031-12-31")
        # Long-lived audit evidence follows the 2035 signature phaseout.
        chain_sig = [
            r for r in by_module["audit_chain"] if r["primitive"] == "Ed25519"
        ]
        self.assertTrue(chain_sig)
        self.assertEqual(chain_sig[0]["deadline"], "2035-12-31")

    def test_ordered_by_deadline(self):
        plan = migration_plan()
        deadlines = [row["deadline"] for row in plan]
        self.assertEqual(deadlines, sorted(deadlines))

    def test_deterministic(self):
        self.assertEqual(migration_plan(), migration_plan())

    def test_every_row_has_action(self):
        for row in migration_plan():
            for key in (
                "module",
                "signs_what",
                "primitive",
                "posture",
                "deadline",
                "action",
            ):
                self.assertIn(key, row)
                self.assertTrue(str(row[key]))


class HybridStubTests(unittest.TestCase):
    def test_hybrid_sign_fail_closed(self):
        v = hybrid_sign(b"payload", key_id="x")
        self.assertEqual(v["verdict"], "deny")
        self.assertIn("not implemented", v["reason"])
        self.assertEqual(
            v["event"]["reason"], "hybrid-signer-not-implemented"
        )


class AuditEventTests(unittest.TestCase):
    def test_denied_event_shape(self):
        ev = timeline_denied_event(
            primitive="Ed25519",
            expires_at="2032-01-01",
            reason="long-lived-asymmetric-credential",
            credential_kind="passport",
        )
        self.assertEqual(ev["event"], QUANTUM_TIMELINE_DENIED_EVENT)
        self.assertEqual(ev["primitive"], "Ed25519")
        self.assertEqual(ev["credential_kind"], "passport")

    def test_warning_event_shape(self):
        ev = timeline_warning_event(
            primitive="Ed25519",
            expires_at="2027-01-01",
            reason="short-lived-inside-phaseout-window",
        )
        self.assertEqual(ev["event"], QUANTUM_TIMELINE_WARNING_EVENT)

    def test_events_feed_audit_chain(self):
        # The event dicts must be chainable records (JSON-serializable).
        import json

        from audit_chain import chain_record

        ev = timeline_denied_event(
            primitive="Ed25519",
            expires_at="2032-01-01",
            reason="long-lived-asymmetric-credential",
        )
        sealed = chain_record(ev, "0" * 64)
        self.assertTrue(sealed["chain_hash"])
        blob = json.dumps(sealed, sort_keys=True)
        self.assertIn(QUANTUM_TIMELINE_DENIED_EVENT, blob)


if __name__ == "__main__":
    unittest.main()
