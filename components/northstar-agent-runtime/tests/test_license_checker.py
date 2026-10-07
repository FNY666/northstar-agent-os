"""Tests for license_checker: policy gate, compat matrix, audit ledger."""

import ast
import unittest
from pathlib import Path

import license_checker
from license_checker import (
    LICENSE_CHECKER_VERSION,
    SCHEMA_PIN,
    LicenseChecker,
    LicenseError,
    UnknownLicenseError,
    BadExpressionError,
    UnknownPolicyError,
    UnknownCheckError,
    SeqOrderError,
    license_checker_audit_event,
)

MODULE_PATH = Path(license_checker.__file__)


class TestPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(LICENSE_CHECKER_VERSION, "license-checker.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.license-checker.v1")

    def test_stdlib_only(self):
        tree = ast.parse(MODULE_PATH.read_text())
        allowed = {"__future__", "hashlib", "re", "threading", "dataclasses",
                   "typing", "json", "canonical_json"}
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add((node.module or "").split(".")[0])
        self.assertTrue(imports <= allowed, imports - allowed)

    def test_main_self_check(self):
        license_checker.main()


class TestPolicyGate(unittest.TestCase):
    def test_permissive_allowed(self):
        lc = LicenseChecker()
        rec = lc.check("MIT", 0)
        self.assertEqual(rec.verdict, "allowed")
        self.assertEqual(rec.max_level, 0)
        self.assertEqual(rec.level_name, "permissive")
        self.assertTrue(rec.pin.startswith("sha256:"))
        self.assertEqual(rec.check_id, "lc-1")
        self.assertEqual(rec.policy, "copyleft-ok")
        self.assertEqual(rec.as_dict()["schema"], SCHEMA_PIN)

    def test_gpl_denied_under_permissive_only(self):
        lc = LicenseChecker()
        rec = lc.check("GPL-3.0-only", 0, policy="permissive-only")
        self.assertEqual(rec.verdict, "denied")
        self.assertEqual(rec.max_level, -1)

    def test_weak_ok_admits_lgpl_not_gpl(self):
        lc = LicenseChecker()
        ok = lc.check("LGPL-2.1-only", 0, policy="weak-ok")
        self.assertEqual(ok.verdict, "allowed")
        no = lc.check("GPL-3.0-only", 1, policy="weak-ok")
        self.assertEqual(no.verdict, "denied")

    def test_dual_license_or_passes_via_any_alternative(self):
        lc = LicenseChecker()
        rec = lc.check("GPL-3.0-only OR MIT", 0, policy="permissive-only")
        self.assertEqual(rec.verdict, "allowed")
        self.assertEqual(rec.max_level, 0)

    def test_and_combination_takes_max_level(self):
        lc = LicenseChecker()
        rec = lc.check("MIT AND Apache-2.0", 0)
        self.assertEqual(rec.verdict, "allowed")
        self.assertEqual(rec.max_level, 0)
        rec2 = lc.check("MIT AND MPL-2.0", 1, policy="weak-ok")
        self.assertEqual(rec2.verdict, "allowed")
        self.assertEqual(rec2.max_level, 1)
        self.assertEqual(rec2.level_name, "weak-copyleft")

    def test_licenseref_denied_fail_closed(self):
        lc = LicenseChecker()
        rec = lc.check("LicenseRef-Internal-1.0", 0)
        self.assertEqual(rec.verdict, "denied")
        self.assertIn("classifiable", rec.reason)

    def test_unknown_token_refused(self):
        lc = LicenseChecker()
        with self.assertRaises(UnknownLicenseError):
            lc.check("MITT", 0)
        # failed mutation consumed its seq: next call needs a fresh seq
        rec = lc.check("MIT", 1)
        self.assertEqual(rec.verdict, "allowed")

    def test_bad_expression_refused(self):
        lc = LicenseChecker()
        with self.assertRaises(BadExpressionError):
            lc.check("MIT AND", 0)
        with self.assertRaises(BadExpressionError):
            lc.check("", 1)
        with self.assertRaises(BadExpressionError):
            lc.check("(MIT OR Apache-2.0", 2)

    def test_unknown_policy_refused(self):
        lc = LicenseChecker()
        with self.assertRaises(UnknownPolicyError):
            lc.check("MIT", 0, policy="everything-ok")

    def test_seq_order(self):
        lc = LicenseChecker()
        lc.check("MIT", 0)
        with self.assertRaises(SeqOrderError):
            lc.check("MIT", 0)
        with self.assertRaises(SeqOrderError):
            lc.check("MIT", True)

    def test_pin_determinism(self):
        a, b = LicenseChecker(), LicenseChecker()
        r1 = a.check("MIT AND Apache-2.0", 5)
        r2 = b.check("MIT AND Apache-2.0", 5)
        self.assertEqual(r1.pin, r2.pin)


class TestCompat(unittest.TestCase):
    def test_same_license_compatible(self):
        lc = LicenseChecker()
        rep = lc.compat("MIT", "MIT", 0)
        self.assertEqual(rep.verdict, "compatible")
        self.assertEqual(rep.combined_level, 0)
        self.assertTrue(rep.pin.startswith("sha256:"))
        self.assertEqual(rep.report_id, "lcr-1")

    def test_mit_with_gpl_compatible(self):
        lc = LicenseChecker()
        rep = lc.compat("MIT", "GPL-3.0-only", 0)
        self.assertEqual(rep.verdict, "compatible")
        self.assertEqual(rep.combined_level, 2)
        self.assertIn("GPL-3.0-only", rep.combined_ids)

    def test_gpl2_only_vs_apache2_incompatible(self):
        lc = LicenseChecker()
        rep = lc.compat("GPL-2.0-only", "Apache-2.0", 0)
        self.assertEqual(rep.verdict, "incompatible")
        self.assertEqual(rep.combined_ids, ())
        self.assertEqual(rep.combined_level, -1)

    def test_gpl2_only_vs_gpl3_only_incompatible(self):
        lc = LicenseChecker()
        rep = lc.compat("GPL-2.0-only", "GPL-3.0-only", 0)
        self.assertEqual(rep.verdict, "incompatible")

    def test_cddl_vs_gpl_incompatible(self):
        lc = LicenseChecker()
        rep = lc.compat("CDDL-1.0", "GPL-2.0-only", 0)
        self.assertEqual(rep.verdict, "incompatible")

    def test_gpl3_vs_apache2_compatible(self):
        lc = LicenseChecker()
        rep = lc.compat("GPL-3.0-only", "Apache-2.0", 0)
        self.assertEqual(rep.verdict, "compatible")

    def test_licenseref_unknown_verdict(self):
        lc = LicenseChecker()
        rep = lc.compat("LicenseRef-Foo", "MIT", 0)
        self.assertEqual(rep.verdict, "unknown")
        self.assertEqual(rep.combined_level, -1)

    def test_dual_license_picks_clean_alternative(self):
        lc = LicenseChecker()
        rep = lc.compat("GPL-2.0-only OR MIT", "Apache-2.0", 0)
        self.assertEqual(rep.verdict, "compatible")

    def test_pair_details_present(self):
        lc = LicenseChecker()
        rep = lc.compat("MIT", "Apache-2.0", 0)
        self.assertEqual(rep.pair_details, (("MIT", "Apache-2.0", "compatible"),))


class TestAudit(unittest.TestCase):
    def test_audit_counts_and_digest(self):
        lc = LicenseChecker()
        lc.check("MIT", 0)
        lc.check("GPL-3.0-only", 1, policy="permissive-only")
        lc.compat("MIT", "GPL-3.0-only", 2)
        lc.compat("GPL-2.0-only", "Apache-2.0", 3)
        lc.compat("LicenseRef-Foo", "MIT", 4)
        rep = lc.audit(5)
        self.assertEqual(rep.checks, 2)
        self.assertEqual(rep.compat_reports, 3)
        self.assertEqual(rep.allowed, 1)
        self.assertEqual(rep.denied, 1)
        self.assertEqual(rep.compatible, 1)
        self.assertEqual(rep.incompatible, 1)
        self.assertEqual(rep.unknown, 1)
        self.assertEqual(rep.record_ids,
                         ("lc-1", "lc-2", "lcr-1", "lcr-2", "lcr-3"))
        self.assertTrue(rep.pin.startswith("sha256:"))

    def test_views_and_lookup_errors(self):
        lc = LicenseChecker()
        lc.check("MIT", 0)
        rec = lc.check_record("lc-1")
        self.assertEqual(rec.expression, "MIT")
        self.assertEqual(lc.check_ids(), ("lc-1",))
        with self.assertRaises(UnknownCheckError):
            lc.check_record("lc-99")
        with self.assertRaises(UnknownCheckError):
            lc.compat_report("lcr-99")

    def test_audit_event_shapes(self):
        ev = license_checker_audit_event("license-checked", 0, check_id="lc-1")
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["event"], "license-checked")
        self.assertEqual(ev["audit_seq"], 0)
        with self.assertRaises(LicenseError):
            license_checker_audit_event("nope", 0)


if __name__ == "__main__":
    unittest.main()
