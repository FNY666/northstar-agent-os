"""Tests for compliance_checker.py."""

import unittest

import compliance_checker as cc_mod
from compliance_checker import (
    BadEvidenceError,
    CheckResult,
    ComplianceChecker,
    ComplianceError,
    ComplianceReport,
    DuplicateControlError,
    EvidenceRecord,
    UnknownControlError,
    compliance_checker_audit_event,
)


def _checker():
    return ComplianceChecker()


def _control(checker, seq=0, cid="CC6.1"):
    return checker.define_control(cid, "SOC2", "desc", ("access-review", "policy-doc"), seq)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(cc_mod.VERSION, "compliance-checker.v1")

    def test_schema_pin(self):
        self.assertEqual(cc_mod.SCHEMA, "northstar.compliance-checker.v1")


class TestDefineControl(unittest.TestCase):
    def test_define_roundtrip(self):
        c = _checker()
        rec = _control(c)
        self.assertEqual(rec.control_id, "CC6.1")
        self.assertEqual(rec.required_evidence, ("access-review", "policy-doc"))
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(c.control("CC6.1"), rec)

    def test_digest_deterministic(self):
        c1, c2 = _checker(), _checker()
        self.assertEqual(_control(c1).digest, _control(c2).digest)

    def test_duplicate_refused(self):
        c = _checker()
        _control(c)
        with self.assertRaises(DuplicateControlError):
            _control(c, seq=1)

    def test_bad_inputs(self):
        c = _checker()
        with self.assertRaises(ComplianceError):
            c.define_control("", "SOC2", "d", ("a",), 0)
        with self.assertRaises(ComplianceError):
            c.define_control("X", "SOC2", "d", (), 1)
        with self.assertRaises(ComplianceError):
            c.define_control("X", "SOC2", "d", ("a", "a"), 1)
        with self.assertRaises(ComplianceError):
            c.define_control("X", "SOC2", "d", ("a",), -1)
        with self.assertRaises(ComplianceError):
            c.define_control("X", "SOC2", "d", ("a",), True)

    def test_unknown_control(self):
        c = _checker()
        with self.assertRaises(UnknownControlError):
            c.control("NOPE")

    def test_seq_monotonic(self):
        c = _checker()
        _control(c, seq=0)
        with self.assertRaises(ComplianceError):
            _control(c, seq=0, cid="CC6.2")

    def test_frozen_record(self):
        rec = _control(_checker())
        with self.assertRaises(AttributeError):
            rec.control_id = "X"  # type: ignore


class TestEvidence(unittest.TestCase):
    def test_attach_roundtrip(self):
        c = _checker()
        _control(c)
        ev = c.attach_evidence("CC6.1", "access-review", {"reviewer": "sec"}, 1)
        self.assertIsInstance(ev, EvidenceRecord)
        self.assertEqual(ev.evidence_id, "ev-1")
        self.assertTrue(ev.payload_digest.startswith("sha256:"))
        self.assertEqual(c.evidence("CC6.1"), (ev,))

    def test_attach_unknown_control(self):
        c = _checker()
        with self.assertRaises(UnknownControlError):
            c.attach_evidence("NOPE", "x", {}, 0)

    def test_payload_not_canonicalizable(self):
        c = _checker()
        _control(c)
        with self.assertRaises(ComplianceError):
            c.attach_evidence("CC6.1", "x", {"v": object()}, 1)

    def test_large_int_refused(self):
        c = _checker()
        _control(c)
        with self.assertRaises(ComplianceError):
            c.attach_evidence("CC6.1", "x", {"v": 2 ** 60}, 1)

    def test_evidence_view_all(self):
        c = _checker()
        _control(c, seq=0)
        c.define_control("CC6.2", "SOC2", "d", ("log",), 1)
        c.attach_evidence("CC6.1", "access-review", {}, 2)
        c.attach_evidence("CC6.2", "log", {}, 3)
        self.assertEqual(len(c.evidence()), 2)
        self.assertEqual(len(c.evidence("CC6.1")), 1)

    def test_evidence_unknown_control_view(self):
        c = _checker()
        with self.assertRaises(UnknownControlError):
            c.evidence("NOPE")

    def test_digest_sensitive_to_content(self):
        c = _checker()
        _control(c)
        e1 = c.attach_evidence("CC6.1", "x", {"v": 1}, 1)
        c2 = _checker()
        _control(c2)
        e2 = c2.attach_evidence("CC6.1", "x", {"v": 2}, 1)
        self.assertNotEqual(e1.payload_digest, e2.payload_digest)


class TestCheck(unittest.TestCase):
    def test_fail_when_missing(self):
        c = _checker()
        _control(c)
        c.attach_evidence("CC6.1", "access-review", {}, 1)
        r = c.check("CC6.1", 2)
        self.assertIsInstance(r, CheckResult)
        self.assertEqual(r.verdict, "fail")
        self.assertEqual(r.missing, ("policy-doc",))
        self.assertEqual(len(r.evidence_ids), 1)

    def test_pass_when_complete(self):
        c = _checker()
        _control(c)
        c.attach_evidence("CC6.1", "access-review", {}, 1)
        c.attach_evidence("CC6.1", "policy-doc", {}, 2)
        r = c.check("CC6.1", 3)
        self.assertEqual(r.verdict, "pass")
        self.assertEqual(r.missing, ())

    def test_fail_no_evidence(self):
        c = _checker()
        _control(c)
        r = c.check("CC6.1", 1)
        self.assertEqual(r.verdict, "fail")
        self.assertEqual(len(r.missing), 2)

    def test_check_unknown_control(self):
        c = _checker()
        with self.assertRaises(UnknownControlError):
            c.check("NOPE", 0)

    def test_check_recheck_overwrites(self):
        c = _checker()
        _control(c)
        c.check("CC6.1", 1)
        c.attach_evidence("CC6.1", "access-review", {}, 2)
        c.attach_evidence("CC6.1", "policy-doc", {}, 3)
        r = c.check("CC6.1", 4)
        self.assertEqual(r.verdict, "pass")


class TestReport(unittest.TestCase):
    def test_report_shape(self):
        c = _checker()
        _control(c, seq=0)
        c.define_control("CC6.2", "SOC2", "d2", ("log",), 1)
        c.attach_evidence("CC6.1", "access-review", {}, 2)
        c.attach_evidence("CC6.1", "policy-doc", {}, 3)
        c.check("CC6.1", 4)
        c.check("CC6.2", 5)
        rep = c.report(6)
        self.assertIsInstance(rep, ComplianceReport)
        self.assertEqual(rep.checked, 2)
        self.assertEqual(rep.passed, 1)
        self.assertEqual(rep.failed, 1)
        self.assertEqual(rep.controls, ("CC6.1", "CC6.2"))
        self.assertTrue(rep.results_digest.startswith("sha256:"))

    def test_report_empty(self):
        rep = _checker().report(0)
        self.assertEqual(rep.checked, 0)
        self.assertEqual(rep.controls, ())

    def test_report_id_monotonic(self):
        c = _checker()
        r1 = c.report(0)
        r2 = c.report(1)
        self.assertNotEqual(r1.report_id, r2.report_id)

    def test_report_digest_deterministic(self):
        c1, c2 = _checker(), _checker()
        for c in (c1, c2):
            _control(c)
            c.attach_evidence("CC6.1", "access-review", {"v": 1}, 1)
            c.attach_evidence("CC6.1", "policy-doc", {"v": 1}, 2)
            c.check("CC6.1", 3)
        self.assertEqual(c1.report(4).results_digest, c2.report(4).results_digest)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        for kind in ("control-defined", "evidence-attached", "checked",
                     "report-generated", "rejected"):
            rec = compliance_checker_audit_event(kind, 0, control_id="CC6.1",
                                                 detail="d")
            self.assertEqual(rec["schema"], "northstar.compliance-checker.v1")
            self.assertEqual(rec["kind"], kind)
            self.assertEqual(rec["seq"], 0)

    def test_audit_unknown_kind(self):
        with self.assertRaises(ComplianceError):
            compliance_checker_audit_event("bogus", 0)

    def test_audit_bad_seq(self):
        with self.assertRaises(ComplianceError):
            compliance_checker_audit_event("checked", -1)


class TestMain(unittest.TestCase):
    def test_main(self):
        cc_mod.main()


if __name__ == "__main__":
    unittest.main()
