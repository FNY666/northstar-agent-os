"""Tests for the DAST scanner (OWASP ZAP shaped, simulated)."""

import ast
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dast_scanner import (
    DAST_SCANNER_VERSION,
    SCHEMA_PIN,
    DASTScanner,
    BadPageError,
    BadURLError,
    DuplicateAttackError,
    DuplicateObservationError,
    SeqOrderError,
    UnknownAttackError,
    UnknownCrawlError,
    UnknownPageError,
    UnknownReportError,
    dast_scanner_audit_event,
)
import dast_scanner as _ds_module

SEED = "https://app.example/"


def make_crawler(seq_start=1):
    sc = DASTScanner()
    sc.load_attack("xss-reflected", "Reflected XSS", "xss", "high", seq_start)
    sc.load_attack("sqli-error", "SQLi error", "injection", "high", seq_start + 1)
    return sc, seq_start + 2


def crawl_two(sc, seq):
    return sc.crawl(
        SEED,
        seq,
        pages=(
            {"url": "https://app.example/", "forms": (), "params": (), "links": ()},
            {
                "url": "https://app.example/search",
                "forms": ("q",),
                "params": ("q",),
                "links": ("https://app.example/",),
            },
        ),
    )


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(DAST_SCANNER_VERSION, "dast-scanner.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.dast-scanner.v1")

    def test_stdlib_only(self):
        tree = ast.parse(Path(_ds_module.__file__).read_text())
        allowed = {
            "hashlib",
            "math",
            "re",
            "threading",
            "dataclasses",
            "typing",
            "__future__",
            "canonical_json",
            "json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestAttackLibrary(unittest.TestCase):
    def test_load_roundtrip(self):
        sc = DASTScanner()
        rec = sc.load_attack("ssrf-basic", "SSRF probe", "ssrf", "medium", 1)
        self.assertEqual(rec.attack_id, "ssrf-basic")
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(sc.attack_template("ssrf-basic"), rec)
        self.assertEqual(sc.attack_ids(), ("ssrf-basic",))

    def test_duplicate_attack_refused(self):
        sc = DASTScanner()
        sc.load_attack("a1", "A", "xss", "low", 1)
        with self.assertRaises(DuplicateAttackError):
            sc.load_attack("a1", "A2", "xss", "low", 2)

    def test_bad_inputs_refused(self):
        sc = DASTScanner()
        with self.assertRaises(ValueError):
            sc.load_attack("Bad_Id", "A", "xss", "low", 1)
        with self.assertRaises(ValueError):
            sc.load_attack("a2", "A", "nope", "low", 1)
        with self.assertRaises(ValueError):
            sc.load_attack("a3", "A", "xss", "critical", 1)
        with self.assertRaises(UnknownAttackError):
            sc.attack_template("missing")

    def test_seq_strictly_increasing(self):
        sc = DASTScanner()
        sc.load_attack("a1", "A", "xss", "low", 1)
        with self.assertRaises(SeqOrderError):
            sc.load_attack("a2", "A", "xss", "low", 1)


class TestCrawl(unittest.TestCase):
    def test_crawl_roundtrip(self):
        sc = DASTScanner()
        cr = crawl_two(sc, 1)
        self.assertEqual(cr.crawl_id, "crawl-1")
        self.assertEqual(cr.seed_url, SEED)
        self.assertEqual(len(cr.pages), 2)
        self.assertTrue(cr.digest.startswith("sha256:"))
        self.assertEqual(sc.crawl_record("crawl-1"), cr)

    def test_bad_seed_refused(self):
        sc = DASTScanner()
        with self.assertRaises(BadURLError):
            sc.crawl("ftp://app.example/", 1, pages=())
        with self.assertRaises(BadURLError):
            sc.crawl("not a url", 1, pages=())

    def test_out_of_scope_page_refused(self):
        sc = DASTScanner()
        with self.assertRaises(BadPageError):
            sc.crawl(
                SEED,
                1,
                pages=({"url": "https://evil.example/p", "forms": (), "params": (), "links": ()},),
            )

    def test_duplicate_page_refused(self):
        sc = DASTScanner()
        page = {"url": "https://app.example/a", "forms": (), "params": (), "links": ()}
        with self.assertRaises(BadPageError):
            sc.crawl(SEED, 1, pages=(page, page))

    def test_unknown_crawl(self):
        sc = DASTScanner()
        with self.assertRaises(UnknownCrawlError):
            sc.crawl_record("crawl-9")


class TestAttack(unittest.TestCase):
    def test_attack_finding(self):
        sc, seq = make_crawler()
        cr = crawl_two(sc, seq)
        ar = sc.attack(
            cr.crawl_id,
            seq + 1,
            observations=(
                {
                    "page_url": "https://app.example/search",
                    "attack_id": "xss-reflected",
                    "evidence": "payload reflected in q",
                },
            ),
        )
        self.assertEqual(ar.report_id, "attack-1")
        self.assertEqual(len(ar.findings), 1)
        f = ar.findings[0]
        self.assertEqual(f.page_url, "https://app.example/search")
        self.assertEqual(f.attack_id, "xss-reflected")
        self.assertEqual(f.severity, "high")
        self.assertTrue(f.digest.startswith("sha256:"))

    def test_unknown_crawl_page_attack_refused(self):
        sc, seq = make_crawler()
        cr = crawl_two(sc, seq)
        with self.assertRaises(UnknownCrawlError):
            sc.attack("crawl-9", seq + 1, observations=())
        with self.assertRaises(UnknownPageError):
            sc.attack(
                cr.crawl_id,
                seq + 2,
                observations=(
                    {
                        "page_url": "https://app.example/never-crawled",
                        "attack_id": "xss-reflected",
                        "evidence": "x",
                    },
                ),
            )
        with self.assertRaises(UnknownAttackError):
            sc.attack(
                cr.crawl_id,
                seq + 3,
                observations=(
                    {
                        "page_url": "https://app.example/search",
                        "attack_id": "nope-attack",
                        "evidence": "x",
                    },
                ),
            )

    def test_duplicate_observation_refused(self):
        sc, seq = make_crawler()
        cr = crawl_two(sc, seq)
        obs = {
            "page_url": "https://app.example/search",
            "attack_id": "xss-reflected",
            "evidence": "x",
        }
        with self.assertRaises(DuplicateObservationError):
            sc.attack(cr.crawl_id, seq + 1, observations=(obs, obs))


class TestReport(unittest.TestCase):
    def test_report_aggregates(self):
        sc, seq = make_crawler()
        cr = crawl_two(sc, seq)
        sc.attack(
            cr.crawl_id,
            seq + 1,
            observations=(
                {
                    "page_url": "https://app.example/search",
                    "attack_id": "sqli-error",
                    "evidence": "sql error",
                },
                {
                    "page_url": "https://app.example/",
                    "attack_id": "xss-reflected",
                    "evidence": "reflected",
                },
            ),
        )
        sc.attack(cr.crawl_id, seq + 2, observations=())
        rep = sc.report(cr.crawl_id, seq + 3)
        self.assertEqual(rep.report_id, "scan-1")
        self.assertEqual(rep.pages_scanned, 2)
        self.assertEqual(rep.attack_reports, 2)
        # deterministic ordering: (url, attack_id)
        self.assertEqual(
            [(f.page_url, f.attack_id) for f in rep.findings],
            [
                ("https://app.example/", "xss-reflected"),
                ("https://app.example/search", "sqli-error"),
            ],
        )
        self.assertEqual(sc.get_report("scan-1"), rep)
        with self.assertRaises(UnknownReportError):
            sc.get_report("scan-9")


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        sc, seq = make_crawler()
        cr = crawl_two(sc, seq)
        rep = sc.report(cr.crawl_id, seq + 1)
        attack = sc.attack_template("xss-reflected")
        ev = dast_scanner_audit_event("reported", seq + 2, crawl=cr, attack=attack, report=rep)
        self.assertEqual(ev["schema"], SCHEMA_PIN)
        self.assertEqual(ev["crawl_id"], cr.crawl_id)
        self.assertEqual(ev["attack_id"], "xss-reflected")
        self.assertEqual(ev["findings"], 0)
        with self.assertRaises(ValueError):
            dast_scanner_audit_event("nope", 1)

    def test_main(self):
        _ds_module.main()


if __name__ == "__main__":
    unittest.main()
