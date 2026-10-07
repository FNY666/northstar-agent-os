"""Targeted tests for the verification badges interface."""

import ast
import unittest
from pathlib import Path

from verification_badges import (
    ACTIVE,
    AUDIT_SCHEMA,
    BADGE_TYPES,
    KIND_AUDIT,
    KIND_ISSUED,
    KIND_REVOKED,
    REVOKED,
    VERIFICATION_BADGES_SCHEMA,
    VERIFICATION_BADGES_VERSION,
    VerificationBadges,
    VerificationBadgesError,
    compute_record_digest,
    main,
    verification_badges_audit_event,
)

MODULE_PATH = Path(__file__).resolve().parent.parent / "verification_badges.py"


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(VERIFICATION_BADGES_VERSION, "verification-badges.v1")
        self.assertEqual(VERIFICATION_BADGES_SCHEMA, "northstar.verification-badges.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")

    def test_stdlib_only(self):
        tree = ast.parse(MODULE_PATH.read_text())
        allowed = {"__future__", "hashlib", "json", "dataclasses", "threading", "typing"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)

    def test_badge_type_vocabulary(self):
        self.assertEqual(
            sorted(BADGE_TYPES),
            ["business", "email", "identity", "phone", "trusted"],
        )


class TestIssue(unittest.TestCase):
    def test_issue_happy_path(self):
        mgr = VerificationBadges()
        rec = mgr.issue(
            subject_id="sub-1", badge_type="email", seq=1,
            evidence="otp:email-link",
        )
        self.assertEqual(rec.badge_id, "badge-1")
        self.assertEqual(rec.status, ACTIVE)
        self.assertEqual(rec.assurance, "low")
        self.assertEqual(rec.issued_seq, 1)
        self.assertEqual(rec.prev_digest, "genesis")
        self.assertEqual(len(rec.record_digest), 64)
        self.assertEqual(compute_record_digest(rec), rec.record_digest)

    def test_issue_identity_assurance(self):
        mgr = VerificationBadges()
        rec = mgr.issue(
            subject_id="sub-1", badge_type="identity", seq=1,
            evidence="kyc:document-v2",
        )
        self.assertEqual(rec.assurance, "substantial")

    def test_issue_unknown_badge_type_refused(self):
        mgr = VerificationBadges()
        with self.assertRaises(VerificationBadgesError):
            mgr.issue(subject_id="sub-1", badge_type="ssn", seq=1,
                      evidence="x")

    def test_issue_empty_subject_refused(self):
        mgr = VerificationBadges()
        with self.assertRaises(VerificationBadgesError):
            mgr.issue(subject_id="  ", badge_type="email", seq=1,
                      evidence="x")

    def test_issue_empty_evidence_refused(self):
        mgr = VerificationBadges()
        with self.assertRaises(VerificationBadgesError):
            mgr.issue(subject_id="sub-1", badge_type="email", seq=1,
                      evidence="")

    def test_issue_duplicate_active_refused(self):
        mgr = VerificationBadges()
        mgr.issue(subject_id="sub-1", badge_type="phone", seq=1,
                  evidence="otp:sms")
        with self.assertRaises(VerificationBadgesError):
            mgr.issue(subject_id="sub-1", badge_type="phone", seq=2,
                      evidence="otp:sms")

    def test_issue_seq_ordering(self):
        mgr = VerificationBadges()
        with self.assertRaises(VerificationBadgesError):
            mgr.issue(subject_id="s", badge_type="email", seq=-1, evidence="x")
        with self.assertRaises(VerificationBadgesError):
            mgr.issue(subject_id="s", badge_type="email", seq=True, evidence="x")
        mgr.issue(subject_id="s", badge_type="email", seq=5, evidence="x")
        with self.assertRaises(VerificationBadgesError):  # rewind
            mgr.issue(subject_id="t", badge_type="email", seq=5, evidence="x")


class TestCheck(unittest.TestCase):
    def test_check_active(self):
        mgr = VerificationBadges()
        mgr.issue(subject_id="sub-1", badge_type="email", seq=1,
                  evidence="otp:email-link", expires_at=100)
        self.assertTrue(mgr.check("sub-1", "email", at_seq=50))

    def test_check_revoked(self):
        mgr = VerificationBadges()
        mgr.issue(subject_id="sub-1", badge_type="email", seq=1,
                  evidence="otp:email-link")
        mgr.revoke("badge-1", seq=2, reason="fraud-signal")
        self.assertFalse(mgr.check("sub-1", "email", at_seq=1))

    def test_check_expired(self):
        mgr = VerificationBadges()
        mgr.issue(subject_id="sub-1", badge_type="email", seq=1,
                  evidence="otp:email-link", expires_at=10)
        self.assertFalse(mgr.check("sub-1", "email", at_seq=10))
        self.assertFalse(mgr.check("sub-1", "email", at_seq=11))

    def test_check_unknown_is_false_not_raise(self):
        mgr = VerificationBadges()
        self.assertFalse(mgr.check("nobody", "email", at_seq=1))
        self.assertFalse(mgr.check("sub-1", "nope", at_seq=1))

    def test_check_reissue_after_revoke(self):
        mgr = VerificationBadges()
        mgr.issue(subject_id="sub-1", badge_type="phone", seq=1,
                  evidence="otp:sms")
        mgr.revoke("badge-1", seq=2, reason="number-changed")
        rec2 = mgr.issue(subject_id="sub-1", badge_type="phone", seq=3,
                         evidence="otp:sms")
        self.assertEqual(rec2.badge_id, "badge-2")
        self.assertTrue(mgr.check("sub-1", "phone", at_seq=3))


class TestRevoke(unittest.TestCase):
    def test_revoke_happy_path(self):
        mgr = VerificationBadges()
        mgr.issue(subject_id="sub-1", badge_type="trusted", seq=1,
                  evidence="org:vetting-board")
        rec = mgr.revoke("badge-1", seq=2, reason="vetting-withdrawn")
        self.assertEqual(rec.status, REVOKED)
        self.assertEqual(rec.seq, 2)
        self.assertEqual(compute_record_digest(rec), rec.record_digest)

    def test_revoke_unknown_refused(self):
        mgr = VerificationBadges()
        with self.assertRaises(VerificationBadgesError):
            mgr.revoke("badge-999", seq=1, reason="x")

    def test_revoke_terminal(self):
        mgr = VerificationBadges()
        mgr.issue(subject_id="sub-1", badge_type="email", seq=1, evidence="x")
        mgr.revoke("badge-1", seq=2, reason="first")
        with self.assertRaises(VerificationBadgesError):
            mgr.revoke("badge-1", seq=3, reason="second")


class TestAudit(unittest.TestCase):
    def test_audit_event_shapes(self):
        ev = verification_badges_audit_event(KIND_ISSUED, 1, badge_id="badge-1")
        self.assertEqual(ev["schema"], AUDIT_SCHEMA)
        self.assertEqual(ev["kind"], KIND_ISSUED)
        self.assertEqual(ev["module"], "verification_badges")
        with self.assertRaises(VerificationBadgesError):
            verification_badges_audit_event("bogus", 1)

    def test_audit_summary(self):
        mgr = VerificationBadges()
        mgr.issue(subject_id="s", badge_type="email", seq=1, evidence="x")
        mgr.revoke("badge-1", seq=2, reason="y")
        ev = mgr.audit(seq=3)
        self.assertEqual(ev["kind"], KIND_AUDIT)
        self.assertEqual(ev["detail"]["active"], 0)
        self.assertEqual(ev["detail"]["revoked"], 1)
        self.assertEqual(len(mgr.audit_log()), 3)


class TestMain(unittest.TestCase):
    def test_main(self):
        main()


if __name__ == "__main__":
    unittest.main()
