"""Targeted tests for the GDPR consent manager interface."""

import ast
import unittest
from pathlib import Path

from consent_manager import (
    AUDIT_SCHEMA,
    CONSENT_MANAGER_SCHEMA,
    CONSENT_MANAGER_VERSION,
    GRANTED,
    KIND_AUDIT,
    KIND_GRANTED,
    KIND_WITHDRAWN,
    WITHDRAWN,
    ConsentError,
    ConsentManager,
    compute_record_digest,
    consent_manager_audit_event,
    main,
)

MODULE_PATH = Path(__file__).resolve().parent.parent / "consent_manager.py"


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(CONSENT_MANAGER_VERSION, "consent-manager.v1")
        self.assertEqual(CONSENT_MANAGER_SCHEMA, "northstar.consent-manager.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")

    def test_stdlib_only(self):
        tree = ast.parse(MODULE_PATH.read_text())
        allowed = {
            "__future__", "hashlib", "hmac", "json", "dataclasses", "typing",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestGrant(unittest.TestCase):
    def test_grant_happy_path(self):
        mgr = ConsentManager()
        rec = mgr.grant(
            subject_id="sub-1", purpose="analytics", scope="personal",
            seq=10, expires_at=100, evidence="ui:checkbox#v3",
        )
        self.assertEqual(rec.status, GRANTED)
        self.assertEqual(rec.lawful_basis, "consent")
        self.assertEqual(rec.granted_seq, 10)
        self.assertEqual(len(rec.record_digest), 64)
        self.assertEqual(compute_record_digest(rec), rec.record_digest)
        self.assertEqual(rec.prev_digest, "genesis")

    def test_grant_requires_evidence(self):
        mgr = ConsentManager()
        with self.assertRaises(ConsentError):
            mgr.grant(subject_id="sub-1", purpose="analytics", scope="personal",
                      seq=10, evidence="")
        with self.assertRaises(ConsentError):
            mgr.grant(subject_id="sub-1", purpose="analytics", scope="personal",
                      seq=10, evidence="   ")

    def test_grant_rejects_nonconsent_lawful_basis(self):
        mgr = ConsentManager()
        with self.assertRaises(ConsentError):
            mgr.grant(subject_id="sub-1", purpose="analytics", scope="personal",
                      seq=10, evidence="ui:checkbox#v3",
                      lawful_basis="legitimate_interests")

    def test_grant_rejects_unknown_scope(self):
        mgr = ConsentManager()
        with self.assertRaises(ConsentError):
            mgr.grant(subject_id="sub-1", purpose="analytics", scope="marketing",
                      seq=10, evidence="ui:checkbox#v3")

    def test_grant_expiry_must_follow_grant_seq(self):
        mgr = ConsentManager()
        with self.assertRaises(ConsentError):
            mgr.grant(subject_id="sub-1", purpose="analytics", scope="personal",
                      seq=10, expires_at=10, evidence="ui:checkbox#v3")
        with self.assertRaises(ConsentError):
            mgr.grant(subject_id="sub-1", purpose="analytics", scope="personal",
                      seq=10, expires_at=5, evidence="ui:checkbox#v3")


class TestConsentCheck(unittest.TestCase):
    def test_consented_happy_path(self):
        mgr = ConsentManager()
        mgr.grant(subject_id="sub-1", purpose="analytics", scope="personal",
                  seq=10, expires_at=100, evidence="ui:checkbox#v3")
        self.assertTrue(mgr.consented(subject_id="sub-1", purpose="analytics",
                                      scope="personal", at_seq=10))
        self.assertTrue(mgr.consented(subject_id="sub-1", purpose="analytics",
                                      scope="personal", at_seq=100))
        # Purpose limitation: exact match only — no wildcards, no subsumption.
        self.assertFalse(mgr.consented(subject_id="sub-1", purpose="marketing",
                                       scope="personal", at_seq=50))
        self.assertFalse(mgr.consented(subject_id="sub-1", purpose="analytics",
                                       scope="special_category", at_seq=50))
        self.assertFalse(mgr.consented(subject_id="nobody", purpose="analytics",
                                       scope="personal", at_seq=50))

    def test_expired_grant_denied(self):
        mgr = ConsentManager()
        mgr.grant(subject_id="sub-1", purpose="analytics", scope="personal",
                  seq=10, expires_at=100, evidence="ui:checkbox#v3")
        self.assertFalse(mgr.consented(subject_id="sub-1", purpose="analytics",
                                       scope="personal", at_seq=101))

    def test_use_before_grant_seq_denied(self):
        mgr = ConsentManager()
        mgr.grant(subject_id="sub-1", purpose="analytics", scope="personal",
                  seq=10, evidence="ui:checkbox#v3")
        self.assertFalse(mgr.consented(subject_id="sub-1", purpose="analytics",
                                       scope="personal", at_seq=9))


class TestWithdraw(unittest.TestCase):
    def test_withdraw_happy_path(self):
        mgr = ConsentManager()
        grant = mgr.grant(subject_id="sub-1", purpose="analytics",
                          scope="personal", seq=10, evidence="ui:checkbox#v3")
        withdrawn = mgr.withdraw(subject_id="sub-1", purpose="analytics",
                                 scope="personal", seq=20)
        self.assertEqual(withdrawn.status, WITHDRAWN)
        self.assertEqual(withdrawn.granted_seq, 10)  # grant lineage preserved
        self.assertEqual(withdrawn.prev_digest, grant.record_digest)
        self.assertEqual(compute_record_digest(withdrawn), withdrawn.record_digest)
        # Withdrawal is immediate: still consented at 19, denied at 20.
        self.assertTrue(mgr.consented(subject_id="sub-1", purpose="analytics",
                                      scope="personal", at_seq=19))
        self.assertFalse(mgr.consented(subject_id="sub-1", purpose="analytics",
                                       scope="personal", at_seq=20))

    def test_withdraw_without_active_grant_raises(self):
        mgr = ConsentManager()
        with self.assertRaises(ConsentError):
            mgr.withdraw(subject_id="sub-1", purpose="analytics",
                         scope="personal", seq=20)  # nothing ever granted
        mgr.grant(subject_id="sub-1", purpose="analytics", scope="personal",
                  seq=10, evidence="ui:checkbox#v3")
        mgr.withdraw(subject_id="sub-1", purpose="analytics", scope="personal",
                     seq=20)
        with self.assertRaises(ConsentError):
            mgr.withdraw(subject_id="sub-1", purpose="analytics",
                         scope="personal", seq=30)  # double withdraw

    def test_regrant_after_withdraw_works(self):
        mgr = ConsentManager()
        grant = mgr.grant(subject_id="sub-1", purpose="analytics",
                          scope="personal", seq=10, evidence="ui:checkbox#v3")
        withdrawn = mgr.withdraw(subject_id="sub-1", purpose="analytics",
                                 scope="personal", seq=20)
        fresh = mgr.grant(subject_id="sub-1", purpose="analytics",
                          scope="personal", seq=30, evidence="ui:checkbox#v4")
        self.assertEqual(fresh.status, GRANTED)
        self.assertEqual(fresh.granted_seq, 30)  # fresh grant, new lineage
        self.assertEqual(fresh.prev_digest, withdrawn.record_digest)  # chain continues
        self.assertNotEqual(fresh.record_digest, grant.record_digest)
        self.assertTrue(mgr.consented(subject_id="sub-1", purpose="analytics",
                                      scope="personal", at_seq=40))


class TestAudit(unittest.TestCase):
    def test_audit_event_shape(self):
        mgr = ConsentManager()
        mgr.grant(subject_id="sub-1", purpose="analytics", scope="personal",
                  seq=10, evidence="ui:checkbox#v3")
        mgr.grant(subject_id="sub-2", purpose="research",
                  scope="special_category", seq=11, evidence="form:signed#7")
        mgr.withdraw(subject_id="sub-2", purpose="research",
                     scope="special_category", seq=12)
        event = mgr.audit(seq=99)
        self.assertEqual(event["schema"], "audit.ndjson/1")
        self.assertEqual(event["kind"], KIND_AUDIT)
        self.assertEqual(event["module"], "consent_manager")
        self.assertEqual(event["detail"]["records"], 2)
        self.assertEqual(event["detail"]["active_grants"], 1)
        self.assertEqual(event["detail"]["withdrawn"], 1)
        self.assertEqual(len(event["detail"]["state_digest"]), 64)
        # Subject filter restricts the audit scope.
        filtered = mgr.audit(seq=100, subject_id="sub-1")
        self.assertEqual(filtered["detail"]["records"], 1)
        self.assertEqual(filtered["detail"]["active_grants"], 1)
        # Transition events are pinned to the audit schema too.
        trail = mgr.audit_trail()
        self.assertEqual(trail[0]["kind"], KIND_GRANTED)
        self.assertEqual(trail[-1]["kind"], KIND_WITHDRAWN)
        for entry in trail:
            self.assertEqual(entry["schema"], "audit.ndjson/1")

    def test_main_self_check_runs(self):
        self.assertIsNone(main())
        event = consent_manager_audit_event(KIND_GRANTED, 1, subject_id="x")
        self.assertEqual(event["schema"], "audit.ndjson/1")


if __name__ == "__main__":
    unittest.main()
