"""Tests for mfa_manager."""

import unittest

from mfa_manager import (
    BACKUP_CODE_COUNT,
    MFA_MANAGER_VERSION,
    SCHEMA_PIN,
    CloneDetectedError,
    DuplicateEnrollmentError,
    MFAManager,
    ReplayedCodeError,
    SeqOrderError,
    UnknownEnrollmentError,
    mfa_manager_audit_event,
)

SEED = b"mfa-manager-test-seed-32bytes!!!!!"


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(MFA_MANAGER_VERSION, "mfa-manager.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.mfa-manager.v1")


class TestEnroll(unittest.TestCase):
    def test_enroll_totp_happy_path(self):
        mgr = MFAManager(seed=SEED)
        rec = mgr.enroll("alice", "totp", 1)
        self.assertEqual(rec.principal, "alice")
        self.assertTrue(rec.cred_id.startswith("totp-"))
        self.assertTrue(rec.secret_b32)
        self.assertTrue(rec.secret_digest.startswith("sha256:"))
        self.assertTrue(rec.digest.startswith("sha256:"))
        d = rec.as_dict()
        self.assertNotIn("secret_b32", d)  # secret never in retained dict
        self.assertNotIn("secret", d)

    def test_enroll_webauthn_happy_path(self):
        mgr = MFAManager(seed=SEED)
        rec = mgr.enroll("alice", "webauthn", 1, rp_id="northstar.local")
        self.assertEqual(rec.rp_id, "northstar.local")
        self.assertTrue(rec.cred_id.startswith("webauthn-"))
        self.assertTrue(rec.key_digest.startswith("sha256:"))

    def test_duplicate_enroll_raises(self):
        mgr = MFAManager(seed=SEED)
        mgr.enroll("alice", "totp", 1)
        with self.assertRaises(DuplicateEnrollmentError):
            mgr.enroll("alice", "totp", 2)

    def test_reenroll_after_disable_mints_fresh_cred_id(self):
        mgr = MFAManager(seed=SEED)
        first = mgr.enroll("alice", "totp", 1)
        mgr.disable("alice", "totp", 2)
        second = mgr.enroll("alice", "totp", 3)
        self.assertNotEqual(first.cred_id, second.cred_id)

    def test_seq_must_increase(self):
        mgr = MFAManager(seed=SEED)
        mgr.enroll("alice", "totp", 5)
        with self.assertRaises(SeqOrderError):
            mgr.enroll("bob", "totp", 5)


class TestTOTPVerify(unittest.TestCase):
    def test_verify_totp_correct_code(self):
        mgr = MFAManager(seed=SEED)
        mgr.enroll("alice", "totp", 1)
        code = mgr.totp_code_for("alice", 100)
        res = mgr.verify("alice", "totp", 2, code=code, step=100)
        self.assertTrue(res.valid)
        self.assertEqual(res.reason, "ok")

    def test_verify_totp_wrong_code(self):
        mgr = MFAManager(seed=SEED)
        mgr.enroll("alice", "totp", 1)
        res = mgr.verify("alice", "totp", 2, code="000000", step=100)
        self.assertFalse(res.valid)
        self.assertEqual(res.reason, "mismatch")

    def test_verify_totp_skew_window(self):
        mgr = MFAManager(seed=SEED)
        mgr.enroll("alice", "totp", 1)
        code = mgr.totp_code_for("alice", 100)
        res = mgr.verify("alice", "totp", 2, code=code, step=101)
        self.assertTrue(res.valid)  # step+1 within skew

    def test_replayed_totp_code_raises(self):
        mgr = MFAManager(seed=SEED)
        mgr.enroll("alice", "totp", 1)
        code = mgr.totp_code_for("alice", 100)
        mgr.verify("alice", "totp", 2, code=code, step=100)
        with self.assertRaises(ReplayedCodeError):
            mgr.verify("alice", "totp", 3, code=code, step=100)


class TestWebAuthnVerify(unittest.TestCase):
    def test_verify_webauthn_happy_path(self):
        mgr = MFAManager(seed=SEED)
        rec = mgr.enroll("alice", "webauthn", 1, rp_id="northstar.local")
        challenge = b"challenge-bytes-0001"
        response = mgr.sign_challenge("alice", rec.cred_id, challenge)
        res = mgr.verify(
            "alice", "webauthn", 2, cred_id=rec.cred_id,
            challenge=challenge, response=response,
            sign_count=1, rp_id="northstar.local",
        )
        self.assertTrue(res.valid)

    def test_webauthn_clone_detection(self):
        mgr = MFAManager(seed=SEED)
        rec = mgr.enroll("alice", "webauthn", 1, rp_id="northstar.local")
        challenge = b"challenge-bytes-0002"
        response = mgr.sign_challenge("alice", rec.cred_id, challenge)
        mgr.verify("alice", "webauthn", 2, cred_id=rec.cred_id,
                   challenge=challenge, response=response,
                   sign_count=5, rp_id="northstar.local")
        with self.assertRaises(CloneDetectedError):
            mgr.verify("alice", "webauthn", 3, cred_id=rec.cred_id,
                       challenge=challenge, response=response,
                       sign_count=5, rp_id="northstar.local")


class TestBackup(unittest.TestCase):
    def test_backup_mint_and_single_use(self):
        mgr = MFAManager(seed=SEED)
        rec, codes = mgr.backup("alice", 1)
        self.assertEqual(len(codes), BACKUP_CODE_COUNT)
        self.assertEqual(rec.remaining(), BACKUP_CODE_COUNT)
        res = mgr.verify("alice", "backup", 2, code=codes[0])
        self.assertTrue(res.valid)
        # Second use of the same code fails: single-use.
        res2 = mgr.verify("alice", "backup", 3, code=codes[0])
        self.assertFalse(res2.valid)
        self.assertEqual(res2.reason, "mismatch")


class TestFailClosed(unittest.TestCase):
    def test_verify_unknown_principal_is_data_not_exception(self):
        mgr = MFAManager(seed=SEED)
        res = mgr.verify("nobody", "totp", 1, code="123456", step=1)
        self.assertFalse(res.valid)
        self.assertEqual(res.reason, "unknown")

    def test_audit_events_and_standalone_event(self):
        mgr = MFAManager(seed=SEED)
        mgr.enroll("alice", "totp", 1)
        mgr.backup("alice", 2)
        events = mgr.audit_events()
        self.assertTrue(len(events) >= 2)
        self.assertTrue(all(e["schema"] == SCHEMA_PIN for e in events))
        ev = mfa_manager_audit_event("verify", "alice", "totp", 3, True)
        self.assertEqual(ev["version"], MFA_MANAGER_VERSION)
        self.assertTrue(ev["ok"])


if __name__ == "__main__":
    unittest.main()
