"""Tests for data_deletion.py (GDPR right to erasure: request/verify/execute)."""

import ast
import unittest
from pathlib import Path

import data_deletion
from data_deletion import (
    DataDeletion,
    DataDeletionError,
    BadCategoryError,
    UnknownRequestError,
    DuplicateRequestError,
    BadRequestError,
    BadVerificationError,
    StateTransitionError,
    LegalHoldError,
    DeletionRequest,
    ErasureReceipt,
    VERSION,
    SCHEMA,
    DATA_CATEGORIES,
    REQUESTED,
    VERIFIED,
    EXECUTED,
    REFUSED,
    EXPIRED,
    VERIFICATION_TTL_S,
    data_deletion_audit_event,
)


def _dd():
    return DataDeletion()


def _seed(dd, subject="alice", category="profile", seq=0):
    return dd.register_records(
        subject, category,
        [{"record_id": "r1", "content": "v1"},
         {"record_id": "r2", "content": "v2"}],
        seq,
    )


def _full_flow(dd, subject="alice", categories=("profile",), t=1000):
    _seed(dd, subject, categories[0], seq=0)
    req = dd.request(subject, list(categories), 1, t)
    dd.verify(req.request_id, req.verification_code, 2, t + 10)
    return req


class TestPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(VERSION, "data-deletion.v1")
        self.assertEqual(SCHEMA, "northstar.data-deletion.v1")
        self.assertEqual(
            DATA_CATEGORIES,
            ("profile", "activity", "messages", "media", "location"),
        )
        self.assertEqual(VERIFICATION_TTL_S, 86_400)

    def test_stdlib_only(self):
        tree = ast.parse(Path(data_deletion.__file__).read_text())
        allowed = {"__future__", "hashlib", "hmac", "threading",
                   "dataclasses", "typing"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(node.module.split(".")[0], allowed)


class TestRequest(unittest.TestCase):
    def test_request_roundtrip(self):
        dd = _dd()
        req = dd.request("alice", ["profile", "messages"], 0, 1000)
        self.assertEqual(req.state, REQUESTED)
        self.assertTrue(req.request_id.startswith("del-"))
        self.assertTrue(req.digest.startswith("sha256:"))
        self.assertTrue(req.verification_code)
        # views after request never carry the code again
        self.assertIsNone(dd.get_request(req.request_id).verification_code)
        self.assertIsInstance(req, DeletionRequest)

    def test_bad_category_refused(self):
        dd = _dd()
        with self.assertRaises(BadCategoryError):
            dd.request("alice", ["biometric_temple_reads"], 0, 1000)
        with self.assertRaises(BadCategoryError):
            dd.request("alice", [], 1, 1000)
        with self.assertRaises(BadCategoryError):
            dd.request("alice", ["profile", "profile"], 2, 1000)

    def test_duplicate_pending_refused(self):
        dd = _dd()
        dd.request("alice", ["profile"], 0, 1000)
        with self.assertRaises(DuplicateRequestError):
            dd.request("alice", ["messages"], 1, 1001)
        # different subject is fine
        req = dd.request("bob", ["profile"], 2, 1000)
        self.assertEqual(req.state, REQUESTED)

    def test_seq_strictly_increasing(self):
        dd = _dd()
        dd.request("alice", ["profile"], 5, 1000)
        with self.assertRaises(BadRequestError):
            dd.request("bob", ["profile"], 5, 1000)
        with self.assertRaises(BadRequestError):
            dd.request("bob", ["profile"], 3, 1000)


class TestVerify(unittest.TestCase):
    def test_verify_success(self):
        dd = _dd()
        req = dd.request("alice", ["profile"], 0, 1000)
        out = dd.verify(req.request_id, req.verification_code, 1, 1100)
        self.assertEqual(out.state, VERIFIED)

    def test_wrong_code_fails_closed(self):
        dd = _dd()
        req = dd.request("alice", ["profile"], 0, 1000)
        with self.assertRaises(BadVerificationError):
            dd.verify(req.request_id, "deadbeefdeadbeef", 1, 1100)
        # stays REQUESTED; failure audits
        self.assertEqual(dd.get_request(req.request_id).state, REQUESTED)
        events = [e["event"] for e in dd.audit_log(req.request_id)]
        self.assertIn("data-deletion.verification_failed", events)

    def test_verify_unknown_request(self):
        dd = _dd()
        with self.assertRaises(UnknownRequestError):
            dd.verify("del-999", "anything", 0, 1000)

    def test_verify_after_ttl_expires(self):
        dd = _dd()
        req = dd.request("alice", ["profile"], 0, 1000)
        out = dd.verify(
            req.request_id, req.verification_code, 1, 1000 + VERIFICATION_TTL_S + 1
        )
        self.assertEqual(out.state, EXPIRED)
        with self.assertRaises(StateTransitionError):
            dd.verify(req.request_id, req.verification_code, 2, 1000 + VERIFICATION_TTL_S + 2)


class TestExecute(unittest.TestCase):
    def test_execute_destroys_and_receipt_proves(self):
        dd = _dd()
        req = _full_flow(dd)
        rcpt = dd.execute(req.request_id, 3, 1011)
        self.assertIsInstance(rcpt, ErasureReceipt)
        self.assertEqual(dd.get_request(req.request_id).state, EXECUTED)
        self.assertTrue(rcpt.proof_digest.startswith("sha256:"))
        self.assertEqual(rcpt.deleted_categories, ("profile",))
        self.assertEqual(len(rcpt.destroyed_record_digests), 2)
        # store really is empty for the erased category
        self.assertEqual(dd.stored_records("alice")["profile"], [])
        # audit trail has all four events in order
        events = [e["event"] for e in dd.audit_log(req.request_id)]
        self.assertEqual(
            events,
            ["data-deletion.requested", "data-deletion.verified",
             "data-deletion.executed"],
        )
        # every audit event is audit.ndjson/1-shaped
        for e in dd.audit_log(req.request_id):
            self.assertEqual(e["schema"], "audit.ndjson/1")

    def test_execute_before_verify_refused(self):
        dd = _dd()
        req = dd.request("alice", ["profile"], 0, 1000)
        with self.assertRaises(StateTransitionError):
            dd.execute(req.request_id, 1, 1001)
        self.assertEqual(dd.get_request(req.request_id).state, REQUESTED)

    def test_execute_twice_refused(self):
        dd = _dd()
        req = _full_flow(dd)
        dd.execute(req.request_id, 3, 1011)
        with self.assertRaises(StateTransitionError):
            dd.execute(req.request_id, 4, 1012)

    def test_legal_hold_refuses_whole_request(self):
        dd = _dd()
        dd.register_records(
            "alice", "messages",
            [{"record_id": "m1", "content": "hello", "legal_hold": True}],
            0,
        )
        req = dd.request("alice", ["messages"], 1, 1000)
        dd.verify(req.request_id, req.verification_code, 2, 1010)
        with self.assertRaises(LegalHoldError):
            dd.execute(req.request_id, 3, 1011)
        self.assertEqual(dd.get_request(req.request_id).state, REFUSED)
        # held data untouched
        recs = dd.stored_records("alice")["messages"]
        self.assertEqual([r.record_id for r in recs], ["m1"])
        events = [e["event"] for e in dd.audit_log(req.request_id)]
        self.assertIn("data-deletion.refused", events)

    def test_failed_mutation_consumes_seq(self):
        dd = _dd()
        dd.request("carol", ["profile"], 10, 1000)
        with self.assertRaises(StateTransitionError):
            dd.execute("del-1", 11, 1001)  # not verified -> burns seq 11
        # seq 11 is consumed even though the mutation failed
        with self.assertRaises(BadRequestError):
            dd.request("dave", ["profile"], 11, 1000)


class TestAuditEventShape(unittest.TestCase):
    def test_audit_event_builder(self):
        e = data_deletion_audit_event(7, "data-deletion.requested",
                                      {"request_id": "del-1"})
        self.assertEqual(e["schema"], "audit.ndjson/1")
        self.assertEqual(e["seq"], 7)
        self.assertEqual(e["module"], SCHEMA)
        self.assertEqual(e["event"], "data-deletion.requested")


if __name__ == "__main__":
    unittest.main()
