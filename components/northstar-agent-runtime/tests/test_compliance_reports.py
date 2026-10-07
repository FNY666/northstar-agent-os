"""Tests for compliance_reports: 15 cases."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from compliance_reports import (
    COMPLIANCE_REPORTS_SCHEMA,
    COMPLIANCE_REPORTS_VERSION,
    VERDICTS,
    FRAMEWORKS,
    AttestationRecord,
    BadAttestationError,
    BadEvidenceError,
    BadFrameworkError,
    ComplianceReports,
    ComplianceReportsError,
    DuplicateFrameworkError,
    EvidenceRecord,
    FrameworkRecord,
    SeqOrderError,
    UnknownControlError,
    UnknownFrameworkError,
    compliance_reports_audit_event,
)

GOOD_DIGEST = "sha256:" + "ab" * 32
GOOD_DIGEST2 = "sha256:" + "cd" * 32


def fresh() -> ComplianceReports:
    return ComplianceReports()


class TestPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(COMPLIANCE_REPORTS_VERSION, "compliance-reports.v1")
        self.assertEqual(COMPLIANCE_REPORTS_SCHEMA, "northstar.compliance-reports.v1")

    def test_framework_catalogs_pinned(self):
        self.assertIn("soc2-type2", FRAMEWORKS)
        self.assertIn("iso27001", FRAMEWORKS)
        self.assertIn("CC1.1", FRAMEWORKS["soc2-type2"])
        self.assertIn("A.5.1", FRAMEWORKS["iso27001"])
        self.assertEqual(
            sorted(FRAMEWORKS["soc2-type1"]), sorted(FRAMEWORKS["soc2-type2"])
        )


class TestFramework(unittest.TestCase):
    def test_define_known(self):
        cr = fresh()
        rec = cr.define_framework("soc2-type2", 1)
        self.assertIsInstance(rec, FrameworkRecord)
        self.assertTrue(rec.verify())
        self.assertEqual(len(rec.controls), len(FRAMEWORKS["soc2-type2"]))
        self.assertIn("soc2-type2", cr.framework_ids())

    def test_define_custom(self):
        cr = fresh()
        rec = cr.define_framework("pci-dss", 1, controls=("REQ-1", "REQ-2"))
        self.assertTrue(rec.verify())
        self.assertEqual(rec.controls, ("REQ-1", "REQ-2"))

    def test_define_duplicate(self):
        cr = fresh()
        cr.define_framework("iso27001", 1)
        with self.assertRaises(DuplicateFrameworkError):
            cr.define_framework("ISO27001", 2)  # case-normalized, dup

    def test_define_bad(self):
        cr = fresh()
        with self.assertRaises(ComplianceReportsError):
            cr.define_framework("", 1)
        with self.assertRaises(BadFrameworkError):
            cr.define_framework("custom-x", 2)  # no controls
        with self.assertRaises(BadFrameworkError):
            cr.define_framework("soc2-type1", 3, controls=("CC1.1",))


class TestEvidence(unittest.TestCase):
    def test_evidence_roundtrip(self):
        cr = fresh()
        cr.define_framework("soc2-type2", 1)
        rec = cr.evidence("soc2-type2", "CC1.1", GOOD_DIGEST, 2,
                          collected_by="auditor-a")
        self.assertIsInstance(rec, EvidenceRecord)
        self.assertTrue(rec.verify())
        self.assertEqual(rec.artifact_digest, GOOD_DIGEST)
        self.assertEqual(len(cr.evidence_for("soc2-type2", "CC1.1")), 1)

    def test_evidence_bad_digest(self):
        cr = fresh()
        cr.define_framework("soc2-type2", 1)
        with self.assertRaises(BadEvidenceError):
            cr.evidence("soc2-type2", "CC1.1", "not-a-digest", 2)

    def test_evidence_duplicate(self):
        cr = fresh()
        cr.define_framework("soc2-type2", 1)
        cr.evidence("soc2-type2", "CC1.1", GOOD_DIGEST, 2)
        with self.assertRaises(BadEvidenceError):
            cr.evidence("soc2-type2", "CC1.1", GOOD_DIGEST, 3)

    def test_evidence_unknown_control(self):
        cr = fresh()
        cr.define_framework("soc2-type2", 1)
        with self.assertRaises(UnknownControlError):
            cr.evidence("soc2-type2", "CC1.9", GOOD_DIGEST, 2)


class TestAttestation(unittest.TestCase):
    def test_attest_happy(self):
        cr = fresh()
        cr.define_framework("soc2-type2", 1)
        cr.evidence("soc2-type2", "CC2.1", GOOD_DIGEST2, 2)
        rec = cr.attest("soc2-type2", "CC2.1", "operating-effectively", 3,
                        attester="auditor-a")
        self.assertIsInstance(rec, AttestationRecord)
        self.assertTrue(rec.verify())
        self.assertEqual(rec.verdict, "operating-effectively")
        self.assertEqual(
            [a.verdict for a in cr.attestations_for("soc2-type2", "CC2.1")],
            ["operating-effectively"],
        )

    def test_attest_needs_evidence(self):
        cr = fresh()
        cr.define_framework("iso27001", 1)
        with self.assertRaises(BadAttestationError):
            cr.attest("iso27001", "A.5.1", "operating-effectively", 2)
        # not-tested may stand alone
        rec = cr.attest("iso27001", "A.5.1", "not-tested", 3)
        self.assertTrue(rec.verify())

    def test_attest_bad_verdict(self):
        cr = fresh()
        cr.define_framework("iso27001", 1)
        cr.evidence("iso27001", "A.5.1", GOOD_DIGEST, 2)
        with self.assertRaises(BadAttestationError):
            cr.attest("iso27001", "A.5.1", "probably-fine", 3)


class TestGenerate(unittest.TestCase):
    def test_generate_aggregates(self):
        cr = fresh()
        cr.define_framework("soc2-type2", 1)
        cr.evidence("soc2-type2", "CC1.1", GOOD_DIGEST, 2)
        cr.evidence("soc2-type2", "CC2.1", GOOD_DIGEST2, 3)
        cr.attest("soc2-type2", "CC1.1", "operating-effectively", 4)
        cr.attest("soc2-type2", "CC2.1", "deficient", 5)
        rep = cr.generate("soc2-type2", 6, period_label="FY2026-Q1")
        self.assertTrue(rep.verify())
        self.assertEqual(rep.controls_with_evidence, 2)
        self.assertEqual(rep.controls_attested, 2)
        self.assertEqual(rep.deficiencies, ("CC2.1",))
        counts = dict(rep.verdict_counts)
        self.assertEqual(counts["operating-effectively"], 1)
        self.assertEqual(counts["deficient"], 1)
        self.assertIn(rep.report_id, cr.report_ids())

    def test_generate_empty_framework(self):
        cr = fresh()
        cr.define_framework("iso27701", 1)
        rep = cr.generate("iso27701", 2)
        self.assertTrue(rep.verify())
        self.assertEqual(rep.controls_with_evidence, 0)
        self.assertEqual(rep.deficiencies, ())
        self.assertEqual(rep.controls_total, len(FRAMEWORKS["iso27701"]))


class TestSeqAndAudit(unittest.TestCase):
    def test_seq_ordering(self):
        cr = fresh()
        cr.define_framework("soc2-type2", 5)
        with self.assertRaises(SeqOrderError):
            cr.define_framework("iso27001", 5)
        with self.assertRaises(SeqOrderError):
            cr.define_framework("iso27001", -1)
        with self.assertRaises(SeqOrderError):
            cr.define_framework("iso27001", True)

    def test_audit_shapes_and_ban(self):
        cr = fresh()
        cr.define_framework("soc2-type2", 1)
        cr.evidence("soc2-type2", "CC1.1", GOOD_DIGEST, 2)
        log = cr.audit_log()
        self.assertEqual(log[0]["kind"], "framework-defined")
        self.assertEqual(log[1]["kind"], "evidence-booked")
        self.assertNotIn("evidence_content", log[1]["detail"])
        ev = compliance_reports_audit_event(
            "attested", {"control_id": "CC1.1"}, 3)
        self.assertEqual(ev["module"], "compliance-reports.v1")
        with self.assertRaises(ComplianceReportsError):
            compliance_reports_audit_event(
                "nope", {"control_id": "x"}, 3)
        with self.assertRaises(ComplianceReportsError):
            compliance_reports_audit_event(
                "evidence-booked", {"evidence_content": b"x"}, 3)


if __name__ == "__main__":
    unittest.main()
