"""Tests for vuln_scanner (unittest house style)."""

import unittest

import vuln_scanner as vs
from vuln_scanner import (
    CVERecord,
    Component,
    DuplicateCVEError,
    DuplicateComponentError,
    Finding,
    ScanReport,
    UnknownComponentError,
    UnknownCVEError,
    UnknownReportError,
    VulnScanner,
    VulnScannerError,
    vuln_scanner_audit_event,
)


def _scanner_with_data():
    sc = VulnScanner()
    sc.register_inventory("c1", "openssl", "1.1.1k", 1)
    sc.register_inventory("c2", "nginx", "1.21.0", 2)
    sc.load_cve("CVE-2021-3449", "openssl", "1.1.1a", "1.1.1l", "high", 3)
    sc.load_cve("CVE-2021-23017", "nginx", "1.0.0", "1.20.1", "medium", 4)
    return sc


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(vs.VULN_SCANNER_VERSION, "vuln-scanner.v1")

    def test_schema_pin(self):
        self.assertEqual(vs.SCHEMA_PIN, "northstar.vuln-scanner.v1")


class TestInventory(unittest.TestCase):
    def test_register_happy_path(self):
        sc = VulnScanner()
        comp = sc.register_inventory("c1", "openssl", "1.1.1k", 1)
        self.assertIsInstance(comp, Component)
        self.assertTrue(comp.digest.startswith("sha256:"))

    def test_register_duplicate_refused(self):
        sc = VulnScanner()
        sc.register_inventory("c1", "openssl", "1.1.1k", 1)
        with self.assertRaises(DuplicateComponentError):
            sc.register_inventory("c1", "openssl", "1.1.1k", 2)

    def test_register_bad_inputs(self):
        sc = VulnScanner()
        with self.assertRaises(TypeError):
            sc.register_inventory("", "openssl", "1.1.1k", 1)
        with self.assertRaises(ValueError):
            sc.register_inventory("c2", "bad name!", "1.0.0", 1)
        with self.assertRaises(ValueError):
            sc.register_inventory("c3", "openssl", "not a version!!", 1)
        with self.assertRaises(TypeError):
            sc.register_inventory("c4", "openssl", "1.0.0", True)

    def test_component_lookup_unknown(self):
        sc = VulnScanner()
        with self.assertRaises(UnknownComponentError):
            sc.component("nope")

    def test_components_sorted(self):
        sc = _scanner_with_data()
        self.assertEqual(sc.components(), ("c1", "c2"))


class TestCveLoading(unittest.TestCase):
    def test_load_happy_path(self):
        sc = VulnScanner()
        rec = sc.load_cve("CVE-2021-3449", "openssl", "1.1.1a", "1.1.1l", "high", 1)
        self.assertIsInstance(rec, CVERecord)
        self.assertTrue(rec.digest.startswith("sha256:"))

    def test_load_duplicate_refused(self):
        sc = VulnScanner()
        sc.load_cve("CVE-2021-3449", "openssl", "1.1.1a", "1.1.1l", "high", 1)
        with self.assertRaises(DuplicateCVEError):
            sc.load_cve("CVE-2021-3449", "openssl", "1.1.1a", "1.1.1l", "high", 2)

    def test_load_bad_cve_id(self):
        sc = VulnScanner()
        with self.assertRaises(ValueError):
            sc.load_cve("not-a-cve", "openssl", "1.0.0", "2.0.0", "high", 1)

    def test_load_bad_severity(self):
        sc = VulnScanner()
        with self.assertRaises(ValueError):
            sc.load_cve("CVE-2021-3449", "openssl", "1.0.0", "2.0.0", "extreme", 1)

    def test_load_inverted_range_refused(self):
        sc = VulnScanner()
        with self.assertRaises(ValueError):
            sc.load_cve("CVE-2021-3449", "openssl", "2.0.0", "1.0.0", "high", 1)

    def test_cve_lookup_unknown(self):
        sc = VulnScanner()
        with self.assertRaises(UnknownCVEError):
            sc.cve("CVE-2099-0001")


class TestMatching(unittest.TestCase):
    def test_match_hit(self):
        sc = _scanner_with_data()
        matches = sc.match_cve("openssl", "1.1.1k", 5)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].cve_id, "CVE-2021-3449")

    def test_match_miss_on_version(self):
        sc = _scanner_with_data()
        self.assertEqual(sc.match_cve("openssl", "1.1.1m", 5), ())
        self.assertEqual(sc.match_cve("openssl", "1.1.0", 5), ())

    def test_match_miss_on_name(self):
        sc = _scanner_with_data()
        self.assertEqual(sc.match_cve("libressl", "1.1.1k", 5), ())

    def test_match_boundary_exclusive_high(self):
        sc = _scanner_with_data()
        # affected_high is exclusive: 1.20.1 itself is not affected
        self.assertEqual(sc.match_cve("nginx", "1.20.1", 5), ())
        # but just below it is
        self.assertEqual(len(sc.match_cve("nginx", "1.20.0", 5)), 1)

    def test_match_bad_inputs(self):
        sc = _scanner_with_data()
        with self.assertRaises(ValueError):
            sc.match_cve("bad name!", "1.0.0", 5)
        with self.assertRaises(TypeError):
            sc.match_cve("openssl", "1.0.0", True)


class TestScan(unittest.TestCase):
    def test_scan_happy_path(self):
        sc = _scanner_with_data()
        rep = sc.scan(10)
        self.assertIsInstance(rep, ScanReport)
        self.assertEqual(rep.components_scanned, 2)
        self.assertEqual(rep.cves_considered, 2)
        self.assertEqual(len(rep.findings), 1)
        f = rep.findings[0]
        self.assertIsInstance(f, Finding)
        self.assertEqual((f.component_id, f.cve_id, f.severity), ("c1", "CVE-2021-3449", "high"))
        self.assertTrue(f.digest.startswith("sha256:"))
        self.assertTrue(rep.digest.startswith("sha256:"))

    def test_scan_empty_inventory(self):
        sc = VulnScanner()
        sc.load_cve("CVE-2021-3449", "openssl", "1.1.1a", "1.1.1l", "high", 1)
        rep = sc.scan(2)
        self.assertEqual(rep.components_scanned, 0)
        self.assertEqual(rep.findings, ())

    def test_scan_empty_cve_db(self):
        sc = VulnScanner()
        sc.register_inventory("c1", "openssl", "1.1.1k", 1)
        rep = sc.scan(2)
        self.assertEqual(rep.cves_considered, 0)
        self.assertEqual(rep.findings, ())

    def test_scan_report_lookup(self):
        sc = _scanner_with_data()
        rep = sc.scan(10)
        self.assertEqual(sc.report(rep.report_id), rep)
        self.assertIn(rep.report_id, sc.reports())

    def test_report_lookup_unknown(self):
        sc = _scanner_with_data()
        with self.assertRaises(UnknownReportError):
            sc.report("scan-999")

    def test_scan_multiple_reports(self):
        sc = _scanner_with_data()
        r1 = sc.scan(10)
        r2 = sc.scan(11)
        self.assertNotEqual(r1.report_id, r2.report_id)
        self.assertEqual(len(sc.reports()), 2)

    def test_scan_findings_deterministic_order(self):
        sc = VulnScanner()
        sc.register_inventory("c9", "libpng", "1.6.36", 1)
        sc.register_inventory("c1", "openssl", "1.1.1k", 2)
        sc.load_cve("CVE-2021-3449", "openssl", "1.1.1a", "1.1.1l", "high", 3)
        sc.load_cve("CVE-2019-7317", "libpng", "1.6.0", "1.6.37", "medium", 4)
        rep = sc.scan(5)
        self.assertEqual(
            [(f.component_id, f.cve_id) for f in rep.findings],
            [("c1", "CVE-2021-3449"), ("c9", "CVE-2019-7317")],
        )


class TestAuditEvents(unittest.TestCase):
    def test_audit_shapes(self):
        sc = _scanner_with_data()
        comp = sc.component("c1")
        cve = sc.cve("CVE-2021-3449")
        rep = sc.scan(10)
        for kind, kw in (
            ("inventory-registered", {"component": comp}),
            ("cve-loaded", {"cve": cve}),
            ("scanned", {"report": rep}),
            ("matched", {}),
        ):
            ev = vuln_scanner_audit_event(kind, 20, **kw)
            self.assertEqual(ev["event"], f"vuln-scanner-{kind}")
            self.assertEqual(ev["audit_seq"], 20)
            self.assertEqual(ev["schema"], vs.SCHEMA_PIN)

    def test_audit_bad_kind(self):
        with self.assertRaises(ValueError):
            vuln_scanner_audit_event("bogus", 1)

    def test_audit_bad_seq(self):
        with self.assertRaises(ValueError):
            vuln_scanner_audit_event("matched", -1)

    def test_audit_type_checks(self):
        with self.assertRaises(TypeError):
            vuln_scanner_audit_event("matched", 1, component="nope")
        with self.assertRaises(TypeError):
            vuln_scanner_audit_event("matched", 1, report="nope")


class TestRecords(unittest.TestCase):
    def test_records_frozen(self):
        sc = _scanner_with_data()
        comp = sc.component("c1")
        with self.assertRaises(AttributeError):
            comp.version = "x"  # type: ignore

    def test_record_as_dict(self):
        sc = _scanner_with_data()
        d = sc.component("c1").as_dict()
        self.assertEqual(d["schema"], vs.SCHEMA_PIN)
        self.assertEqual(d["version_pin"], vs.VULN_SCANNER_VERSION)


class TestConcurrency(unittest.TestCase):
    def test_threads_register(self):
        import threading

        sc = VulnScanner()
        errs = []

        def worker(n):
            try:
                sc.register_inventory(f"c{n}", f"pkg{n}", f"1.0.{n}", n)
            except Exception as e:  # noqa: BLE001
                errs.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errs, [])
        self.assertEqual(len(sc.components()), 8)


class TestStdlibOnly(unittest.TestCase):
    def test_stdlib_only(self):
        import ast
        from pathlib import Path

        path = Path(__file__).resolve().parent.parent / "vuln_scanner.py"
        tree = ast.parse(path.read_text())
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.level == 0:
                    imports.add(node.module.split(".")[0])
        allowed = {"__future__", "hashlib", "json", "re", "threading", "dataclasses", "typing", "canonical_json"}
        self.assertLessEqual(imports, allowed, f"non-stdlib imports: {imports - allowed}")


if __name__ == "__main__":
    unittest.main()
