"""Tests for coverage_reporter."""

import unittest

from coverage_reporter import (
    COVERAGE_REPORTER_VERSION,
    SCHEMA_PIN,
    BadLineError,
    CoverageError,
    CoverageReporter,
    DuplicateSourceError,
    SeqOrderError,
    UnknownSourceError,
    ValidationError,
    coverage_reporter_audit_event,
)


class TestVersionPins(unittest.TestCase):
    def test_pins(self):
        self.assertEqual(COVERAGE_REPORTER_VERSION, "coverage-reporter.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.coverage-reporter.v1")


class TestRegisterSource(unittest.TestCase):
    def setUp(self):
        self.r = CoverageReporter()

    def test_roundtrip(self):
        rec = self.r.register_source("a.py", 100, 0)
        self.assertEqual(rec.file_id, "a.py")
        self.assertEqual(rec.lines_total, 100)
        self.assertTrue(rec.pin.startswith("sha256:"))

    def test_duplicate(self):
        self.r.register_source("a.py", 100, 0)
        with self.assertRaises(DuplicateSourceError):
            self.r.register_source("a.py", 50, 1)

    def test_bad_lines_total(self):
        for bad in (0, -5, True, "10", 2_000_000):
            with self.assertRaises(ValidationError):
                self.r.register_source(f"f-{bad}.py", bad, 0)  # type: ignore[arg-type]

    def test_bad_file_id(self):
        with self.assertRaises(ValidationError):
            self.r.register_source("", 10, 0)

    def test_seq_order(self):
        self.r.register_source("a.py", 10, 5)
        with self.assertRaises(SeqOrderError):
            self.r.register_source("b.py", 10, 5)
        with self.assertRaises(SeqOrderError):
            self.r.register_source("b.py", 10, True)  # type: ignore[arg-type]

    def test_source_view(self):
        rec = self.r.register_source("a.py", 10, 0)
        self.assertEqual(self.r.source("a.py"), rec)
        with self.assertRaises(UnknownSourceError):
            self.r.source("nope.py")
        self.assertEqual(self.r.file_ids(), ("a.py",))


class TestMeasure(unittest.TestCase):
    def setUp(self):
        self.r = CoverageReporter()
        self.r.register_source("a.py", 10, 0)

    def test_measure_roundtrip(self):
        rec = self.r.measure("a.py", [1, 2, 3], 1)
        self.assertEqual(rec.covered, (1, 2, 3))
        self.assertEqual(rec.missed, (4, 5, 6, 7, 8, 9, 10))
        self.assertEqual(rec.covered_count, 3)
        self.assertEqual(rec.percent_bp, 3000)
        self.assertTrue(rec.verify())

    def test_measure_dedupes_and_sorts(self):
        rec = self.r.measure("a.py", [3, 1, 3, 2], 1)
        self.assertEqual(rec.covered, (1, 2, 3))

    def test_measure_unknown_source(self):
        with self.assertRaises(UnknownSourceError):
            self.r.measure("ghost.py", [1], 1)

    def test_measure_bad_lines(self):
        for i, bad in enumerate(([0], [11], ["x"], [2.5], [True])):
            with self.assertRaises(BadLineError):
                self.r.measure("a.py", bad, 10 + i)

    def test_measure_not_iterable(self):
        with self.assertRaises(BadLineError):
            self.r.measure("a.py", 5, 1)  # type: ignore[arg-type]

    def test_measurement_view(self):
        rec = self.r.measure("a.py", [1], 1)
        self.assertEqual(self.r.measurement("a.py"), rec)
        with self.assertRaises(UnknownSourceError):
            self.r.measurement("ghost.py")


class TestReportAnnotate(unittest.TestCase):
    def setUp(self):
        self.r = CoverageReporter()
        self.r.register_source("a.py", 10, 0)
        self.r.register_source("b.py", 20, 1)
        self.r.measure("a.py", [1, 2, 3, 4, 5], 2)
        self.r.measure("b.py", [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 3)

    def test_report_aggregate(self):
        rep = self.r.report(4)
        self.assertEqual(rep.files, ("a.py", "b.py"))
        self.assertEqual(rep.lines_total, 30)
        self.assertEqual(rep.covered_total, 15)
        self.assertEqual(rep.percent_bp, 5000)
        self.assertTrue(rep.pin.startswith("sha256:"))

    def test_report_empty(self):
        r2 = CoverageReporter()
        rep = r2.report(0)
        self.assertEqual(rep.files, ())
        self.assertEqual(rep.percent_bp, 0)

    def test_annotate(self):
        ann = self.r.annotate("a.py", 4)
        self.assertEqual(len(ann.lines), 10)
        self.assertEqual(ann.covered_count, 5)
        self.assertEqual(ann.missed_count, 5)
        self.assertTrue(ann.lines[0]["covered"])
        self.assertFalse(ann.lines[5]["covered"])
        self.assertTrue(ann.verify())

    def test_annotate_unknown(self):
        with self.assertRaises(UnknownSourceError):
            self.r.annotate("ghost.py", 4)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        r = CoverageReporter()
        r.register_source("a.py", 10, 0)
        r.measure("a.py", [1], 1)
        kinds = [e["kind"] for e in r.audit_log()]
        self.assertEqual(kinds, ["source-registered", "measured"])
        for e in r.audit_log():
            self.assertEqual(e["schema"], "audit.ndjson/1")
            self.assertTrue(e["pin"].startswith("sha256:"))

    def test_audit_bad_kind(self):
        with self.assertRaises(CoverageError):
            coverage_reporter_audit_event("bogus", 0, {})


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        import coverage_reporter
        coverage_reporter.main()


if __name__ == "__main__":
    unittest.main()
