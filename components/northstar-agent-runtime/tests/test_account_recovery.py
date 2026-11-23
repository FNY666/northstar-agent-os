"""Tests for account_recovery."""

import unittest

from account_recovery import (
    ACCOUNT_RECOVERY_VERSION,
    CODE_DIGITS,
    AccountRecovery,
    AlreadyConsumedError,
    DuplicateRequestError,
    NotVerifiedError,
    RequestExpiredError,
    RequestLockedError,
    SCHEMA_PIN,
    SeqOrderError,
    TokenReplayError,
    UnknownRequestError,
    UnknownTokenError,
    account_recovery_audit_event,
)

SEED = b"account-recovery-test-seed-32bytes!!"


def fresh() -> AccountRecovery:
    return AccountRecovery(seed=SEED)


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(ACCOUNT_RECOVERY_VERSION, "account-recovery.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.account-recovery.v1")


class TestInitiate(unittest.TestCase):
    def test_happy_path(self):
        ar = fresh()
        out = ar.initiate("acct-1", "user@example.com", at_seq=1)
        req = out["request"]
        self.assertEqual(req["account_id"], "acct-1")
        self.assertEqual(req["state"], "pending")
        self.assertEqual(len(out["code"]), CODE_DIGITS)
        self.assertTrue(out["code"].isdigit())

    def test_deterministic_code_with_seed(self):
        a = fresh().initiate("acct-1", "u@x.com", at_seq=1)["code"]
        b = fresh().initiate("acct-1", "u@x.com", at_seq=1)["code"]
        self.assertEqual(a, b)

    def test_duplicate_pending_request(self):
        ar = fresh()
        ar.initiate("acct-1", "u@x.com", at_seq=1)
        with self.assertRaises(DuplicateRequestError):
            ar.initiate("acct-1", "u@x.com", at_seq=2)

    def test_bad_channel(self):
        with self.assertRaises(ValueError):
            fresh().initiate("acct-1", "u@x.com", channel="pigeon", at_seq=1)

    def test_bad_ttl(self):
        with self.assertRaises(ValueError):
            fresh().initiate("acct-1", "u@x.com", ttl_seqs=0, at_seq=1)


class TestVerify(unittest.TestCase):
    def test_verify_happy_path(self):
        ar = fresh()
        out = ar.initiate("acct-1", "u@x.com", at_seq=1)
        res = ar.verify(out["request"]["request_id"], out["code"], at_seq=2)
        self.assertTrue(res["valid"])
        self.assertEqual(res["state"], "verified")

    def test_wrong_code_reports_remaining(self):
        ar = fresh()
        out = ar.initiate("acct-1", "u@x.com", max_attempts=3, at_seq=1)
        rid = out["request"]["request_id"]
        res = ar.verify(rid, "000000", at_seq=2)
        self.assertFalse(res["valid"])
        self.assertEqual(res["attempts_remaining"], 2)

    def test_lockout_after_max_attempts(self):
        ar = fresh()
        out = ar.initiate("acct-1", "u@x.com", max_attempts=2, at_seq=1)
        rid = out["request"]["request_id"]
        ar.verify(rid, "000000", at_seq=2)
        res = ar.verify(rid, "111111", at_seq=3)
        self.assertEqual(res["state"], "locked")
        with self.assertRaises(RequestLockedError):
            ar.verify(rid, out["code"], at_seq=4)

    def test_expired_code(self):
        ar = fresh()
        out = ar.initiate("acct-1", "u@x.com", ttl_seqs=5, at_seq=1)
        rid = out["request"]["request_id"]
        res = ar.verify(rid, out["code"], at_seq=10)
        self.assertFalse(res["valid"])
        self.assertEqual(res["state"], "expired")

    def test_unknown_request(self):
        with self.assertRaises(UnknownRequestError):
            fresh().verify("rcv-999999", "000000", at_seq=1)

    def test_seq_order_enforced(self):
        ar = fresh()
        out = ar.initiate("acct-1", "u@x.com", at_seq=5)
        with self.assertRaises(SeqOrderError):
            ar.verify(out["request"]["request_id"], out["code"], at_seq=5)

    def test_wrong_code_type_raises(self):
        ar = fresh()
        out = ar.initiate("acct-1", "u@x.com", at_seq=1)
        with self.assertRaises(TypeError):
            ar.verify(out["request"]["request_id"], 123456, at_seq=2)


class TestComplete(unittest.TestCase):
    def _verified(self, ar, seq=1):
        out = ar.initiate("acct-1", "u@x.com", at_seq=seq)
        rid = out["request"]["request_id"]
        ar.verify(rid, out["code"], at_seq=seq + 1)
        return ar, rid

    def test_complete_happy_path(self):
        ar, rid = self._verified(fresh())
        out = ar.complete(rid, at_seq=3)
        self.assertTrue(out["recovery_token"].startswith("nrt_"))
        self.assertEqual(ar.get(rid)["state"], "consumed")

    def test_complete_requires_verified(self):
        ar = fresh()
        rid = ar.initiate("acct-1", "u@x.com", at_seq=1)["request"]["request_id"]
        with self.assertRaises(NotVerifiedError):
            ar.complete(rid, at_seq=2)

    def test_complete_twice_raises(self):
        ar, rid = self._verified(fresh())
        ar.complete(rid, at_seq=3)
        with self.assertRaises(AlreadyConsumedError):
            ar.complete(rid, at_seq=4)

    def test_token_redeem_once(self):
        ar, rid = self._verified(fresh())
        token = ar.complete(rid, at_seq=3)["recovery_token"]
        self.assertEqual(ar.redeem_token(token), "acct-1")
        with self.assertRaises(TokenReplayError):
            ar.redeem_token(token)

    def test_unknown_token(self):
        with self.assertRaises(UnknownTokenError):
            fresh().redeem_token("nrt_" + "00" * 24)

    def test_no_secrets_in_record_or_audit(self):
        ar = fresh()
        out = ar.initiate("acct-1", "u@x.com", at_seq=1)
        code, token = out["code"], None
        rid = out["request"]["request_id"]
        ar.verify(rid, code, at_seq=2)
        token = ar.complete(rid, at_seq=3)["recovery_token"]
        record = repr(ar.get(rid))
        audit = repr(ar.audit_log())
        for secret in (code, token):
            self.assertNotIn(secret, record)
            self.assertNotIn(secret, audit)

    def test_audit_event_helper(self):
        ev = account_recovery_audit_event("recovery.initiated", {"a": 1})
        self.assertEqual(ev["schema"], SCHEMA_PIN)
        self.assertEqual(ev["module_version"], ACCOUNT_RECOVERY_VERSION)


if __name__ == "__main__":
    unittest.main()
