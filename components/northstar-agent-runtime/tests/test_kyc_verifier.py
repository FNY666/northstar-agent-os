"""Tests for kyc_verifier (15 tests, stdlib unittest, deterministic)."""

from __future__ import annotations

import unittest

from kyc_verifier import (
    CHECKS,
    Case,
    CaseStatus,
    CheckResult,
    Document,
    InvalidDocumentError,
    KYCError,
    KYCVerifier,
    MissingRequirementError,
    UnknownCaseError,
    BadSeqError,
    VerificationReport,
    _audit_event,
    _canon,
    _pin,
)


def _clean_docs(name="Ada Applicant", expiry=10_000):
    return (
        Document(doc_id="P-1", doc_type="passport", holder_name=name,
                 issuer="Exampleland", expiry_seq=expiry),
        Document(doc_id="U-1", doc_type="utility_bill", holder_name=name,
                 issuer="Example Power", expiry_seq=expiry),
    )


class SubmitTests(unittest.TestCase):
    def test_submit_clean_case_state_submitted(self):
        v = KYCVerifier()
        case = v.submit(case_id="c1", holder_name="Ada",
                       documents=_clean_docs(), seq=1)
        self.assertIsInstance(case, Case)
        self.assertEqual(case.state, "submitted")
        self.assertEqual(case.case_id, "c1")
        self.assertEqual(case.submitted_seq, 1)
        self.assertIsNone(case.decision_seq)
        self.assertTrue(case.case_pin.startswith("sha256:"))

    def test_submit_missing_government_id_rejected(self):
        v = KYCVerifier()
        docs = (Document(doc_id="U-1", doc_type="utility_bill",
                         holder_name="Ada", issuer="EP", expiry_seq=9),)
        with self.assertRaises(MissingRequirementError):
            v.submit(case_id="c1", holder_name="Ada", documents=docs, seq=1)

    def test_submit_missing_address_proof_rejected(self):
        v = KYCVerifier()
        docs = (Document(doc_id="P-1", doc_type="passport",
                         holder_name="Ada", issuer="EL", expiry_seq=9),)
        with self.assertRaises(MissingRequirementError):
            v.submit(case_id="c1", holder_name="Ada", documents=docs, seq=1)

    def test_submit_enhanced_requires_selfie(self):
        v = KYCVerifier()
        with self.assertRaises(MissingRequirementError):
            v.submit(case_id="c1", holder_name="Ada",
                     documents=_clean_docs(), assurance_level="enhanced",
                     seq=1)

    def test_submit_unknown_doc_type_rejected(self):
        with self.assertRaises(InvalidDocumentError):
            Document(doc_id="X-1", doc_type="alien_passport",
                     holder_name="Ada", issuer="Mars", expiry_seq=9)

    def test_submit_non_increasing_seq_rejected(self):
        v = KYCVerifier()
        v.submit(case_id="c1", holder_name="Ada", documents=_clean_docs(),
                 seq=5)
        with self.assertRaises(BadSeqError):
            v.submit(case_id="c2", holder_name="Bob", documents=_clean_docs(),
                     seq=5)

    def test_submit_duplicate_case_id_rejected(self):
        v = KYCVerifier()
        v.submit(case_id="c1", holder_name="Ada", documents=_clean_docs(),
                 seq=1)
        with self.assertRaises(KYCError):
            v.submit(case_id="c1", holder_name="Ada", documents=_clean_docs(),
                     seq=2)


class VerifyTests(unittest.TestCase):
    def test_verify_clean_case_approved(self):
        v = KYCVerifier()
        v.submit(case_id="c1", holder_name="Ada", documents=_clean_docs(),
                 seq=1)
        report = v.verify(case_id="c1", seq=2)
        self.assertIsInstance(report, VerificationReport)
        self.assertEqual(report.decision, "approved")
        self.assertEqual(report.risk_score, 0)
        self.assertEqual(len(report.checks), len(CHECKS))
        self.assertTrue(all(c.passed for c in report.checks))
        self.assertTrue(report.decision_pin.startswith("sha256:"))

    def test_verify_tampered_document_rejected(self):
        v = KYCVerifier()
        docs = (
            Document(doc_id="P-1", doc_type="passport", holder_name="Ada",
                     issuer="EL", expiry_seq=10_000, tampered=True),
            Document(doc_id="U-1", doc_type="utility_bill", holder_name="Ada",
                     issuer="EP", expiry_seq=10_000),
        )
        v.submit(case_id="c1", holder_name="Ada", documents=docs, seq=1)
        report = v.verify(case_id="c1", seq=2)
        self.assertEqual(report.decision, "rejected")
        failed = [c for c in report.checks if not c.passed]
        self.assertEqual([c.name for c in failed], ["document_authenticity"])
        self.assertGreater(report.risk_score, 0)

    def test_verify_sanctions_hit_rejected(self):
        v = KYCVerifier()
        docs = (
            Document(doc_id="P-1", doc_type="passport", holder_name="Ada",
                     issuer="EL", expiry_seq=10_000, sanctions_hit=True),
            Document(doc_id="U-1", doc_type="utility_bill", holder_name="Ada",
                     issuer="EP", expiry_seq=10_000),
        )
        v.submit(case_id="c1", holder_name="Ada", documents=docs, seq=1)
        report = v.verify(case_id="c1", seq=2)
        self.assertEqual(report.decision, "rejected")
        failed = [c for c in report.checks if not c.passed]
        self.assertIn("sanctions_screening", [c.name for c in failed])

    def test_verify_expired_id_rejected(self):
        v = KYCVerifier()
        v.submit(case_id="c1", holder_name="Ada",
                 documents=_clean_docs(expiry=10), seq=1)
        report = v.verify(case_id="c1", seq=50)
        self.assertEqual(report.decision, "rejected")
        failed = [c for c in report.checks if not c.passed]
        self.assertIn("document_expiry", [c.name for c in failed])

    def test_verify_soft_fail_goes_to_manual_review(self):
        v = KYCVerifier()
        docs = (
            Document(doc_id="P-1", doc_type="passport", holder_name="Ada",
                     issuer="EL", expiry_seq=10_000),
            Document(doc_id="U-1", doc_type="utility_bill", holder_name="Ada",
                     issuer="EP", expiry_seq=10_000, address_ok=False),
        )
        v.submit(case_id="c1", holder_name="Ada", documents=docs, seq=1)
        report = v.verify(case_id="c1", seq=2)
        self.assertEqual(report.decision, "manual_review")
        self.assertGreater(report.risk_score, 0)

    def test_verify_unknown_case_rejected(self):
        v = KYCVerifier()
        with self.assertRaises(UnknownCaseError):
            v.verify(case_id="nope", seq=1)


class StatusTests(unittest.TestCase):
    def test_status_tracks_decision(self):
        v = KYCVerifier()
        v.submit(case_id="c1", holder_name="Ada", documents=_clean_docs(),
                 seq=1)
        before = v.status("c1")
        self.assertEqual(before.state, "submitted")
        self.assertIsNone(before.last_decision_seq)
        v.verify(case_id="c1", seq=2)
        after = v.status("c1")
        self.assertIsInstance(after, CaseStatus)
        self.assertEqual(after.state, "approved")
        self.assertEqual(after.last_decision_seq, 2)
        self.assertEqual(after.document_count, 2)
        self.assertTrue(after.decision_pin.startswith("sha256:"))

    def test_status_unknown_case_rejected(self):
        v = KYCVerifier()
        with self.assertRaises(UnknownCaseError):
            v.status("nope")


class AuditAndEncodingTests(unittest.TestCase):
    def test_audit_log_shapes(self):
        v = KYCVerifier()
        v.submit(case_id="c1", holder_name="Ada", documents=_clean_docs(),
                 seq=1)
        v.verify(case_id="c1", seq=2)
        log = v.audit_log()
        self.assertEqual(len(log), 2)
        self.assertEqual(log[0]["stream"], "audit.ndjson/1")
        self.assertEqual(log[0]["event"], "kyc.submitted")
        self.assertEqual(log[1]["event"], "kyc.verified")
        self.assertEqual(log[1]["detail"]["decision"], "approved")

    def test_canon_bool_not_int(self):
        self.assertNotEqual(_canon(True), _canon(1))
        self.assertNotEqual(_canon(False), _canon(0))

    def test_pin_deterministic(self):
        self.assertEqual(_pin("a", 1, True), _pin("a", 1, True))
        self.assertNotEqual(_pin("a", 1, True), _pin("a", 1, False))


class MiscTests(unittest.TestCase):
    def test_check_result_unknown_name_rejected(self):
        with self.assertRaises(KYCError):
            CheckResult(name="mind_reading", passed=True, hard_fail=False,
                        detail="x")

    def test_audit_event_shape(self):
        e = _audit_event(seq=3, event="kyc.submitted", case_id="c1",
                         detail={"k": "v"})
        self.assertEqual(e["stream"], "audit.ndjson/1")
        self.assertEqual(e["seq"], 3)
        self.assertEqual(e["case_id"], "c1")


if __name__ == "__main__":
    unittest.main()
