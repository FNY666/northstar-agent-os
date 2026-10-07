"""Targeted tests for excel_handler (sheet/cell/formula content model)."""

import ast
import unittest

import excel_handler
from excel_handler import (
    EXCEL_HANDLER_VERSION,
    SCHEMA_PIN,
    BadRefError,
    DuplicateSheetError,
    EvalError,
    ExcelHandler,
    FormulaError,
    SeqOrderError,
    UnknownSheetError,
    ValidationError,
    excel_handler_audit_event,
    parse_ref,
)


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(EXCEL_HANDLER_VERSION, "excel-handler.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.excel-handler.v1")
        self.assertEqual(excel_handler.EXCEL_HANDLER_VERSION, EXCEL_HANDLER_VERSION)

    def test_stdlib_only(self):
        tree = ast.parse(open(excel_handler.__file__).read())
        allowed = {
            "__future__", "hashlib", "re", "threading", "dataclasses",
            "typing", "json", "canonical_json",  # canonical_json is the
            # in-repo optional canonicalizer import-guarded for standalone use
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed, a.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestSheets(unittest.TestCase):
    def setUp(self):
        self.h = ExcelHandler()

    def test_create_and_lookup(self):
        rec = self.h.create_sheet("s1", "Budget", 0)
        self.assertEqual(rec.sheet_id, "s1")
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(self.h.sheet("s1"), rec)
        self.assertEqual(self.h.sheet_names(), ["Budget"])

    def test_duplicate_id_and_name(self):
        self.h.create_sheet("s1", "Budget", 0)
        # a failed mutation consumes its seq (fail-closed ledger position)
        with self.assertRaises(DuplicateSheetError):
            self.h.create_sheet("s1", "Other", 1)
        with self.assertRaises(DuplicateSheetError):
            self.h.create_sheet("s2", "Budget", 2)

    def test_unknown_sheet(self):
        with self.assertRaises(UnknownSheetError):
            self.h.sheet("nope")
        with self.assertRaises(UnknownSheetError):
            self.h.cell("nope", "A1", 1, 0)
        with self.assertRaises(UnknownSheetError):
            self.h.formula("nope", "A1", "=SUM(A1:A2)", 0)

    def test_seq_must_increase(self):
        self.h.create_sheet("s1", "Budget", 5)
        with self.assertRaises(SeqOrderError):
            self.h.create_sheet("s2", "Other", 5)
        with self.assertRaises(SeqOrderError):
            self.h.create_sheet("s2", "Other", 2)


class TestRefs(unittest.TestCase):
    def test_parse_ref_happy(self):
        canon, col, row = parse_ref("B12")
        self.assertEqual((canon, col, row), ("B12", 2, 12))
        self.assertEqual(parse_ref("a1")[0], "A1")  # normalized to upper
        self.assertEqual(parse_ref("XFD1048576")[1:], (16384, 1048576))

    def test_parse_ref_refusals(self):
        for bad in ["", "A0", "A", "1", "XFE1", "A1048577", "A-1",
                    "a b1", "AA:1", 12, None, "AAAA1"]:
            with self.assertRaises(BadRefError, msg=bad):
                parse_ref(bad)


class TestCells(unittest.TestCase):
    def setUp(self):
        self.h = ExcelHandler()
        self.h.create_sheet("s1", "Budget", 0)

    def test_set_and_read(self):
        rec = self.h.cell("s1", "C3", 42, 1)
        self.assertEqual(rec.value, 42)
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(self.h.cell_value("s1", "C3"), 42)
        self.assertIsNone(self.h.cell_value("s1", "C4"))  # unset

    def test_value_refusals(self):
        with self.assertRaises(ValidationError):
            self.h.cell("s1", "A1", 1.5, 1)      # floats refused
        with self.assertRaises(ValidationError):
            self.h.cell("s1", "A1", True, 1)     # bools refused
        with self.assertRaises(ValidationError):
            self.h.cell("s1", "A1", 2 ** 53, 1)  # beyond +-2^53
        with self.assertRaises(ValidationError):
            self.h.cell("s1", "A1", [1], 1)      # wrong type

    def test_digest_deterministic(self):
        r1 = self.h.cell("s1", "A1", 7, 1)
        h2 = ExcelHandler()
        h2.create_sheet("s1", "Budget", 0)
        r2 = h2.cell("s1", "A1", 7, 1)
        self.assertEqual(r1.digest, r2.digest)


class TestFormulas(unittest.TestCase):
    def setUp(self):
        self.h = ExcelHandler()
        self.h.create_sheet("s1", "Budget", 0)
        self.h.cell("s1", "A1", 10, 1)
        self.h.cell("s1", "A2", 20, 2)
        self.h.cell("s1", "A3", 30, 3)

    def test_sum(self):
        f = self.h.formula("s1", "B1", "=SUM(A1:A3)", 4)
        self.assertEqual(f.function, "SUM")
        self.assertEqual(len(f.range_refs), 3)
        r = self.h.evaluate("s1", "B1", 5)
        self.assertEqual(r.value, 60)
        self.assertEqual(r.formula_digest, f.digest)

    def test_avg_exact_and_rational(self):
        self.h.formula("s1", "B2", "=AVG(A1:A2)", 4)
        self.assertEqual(self.h.evaluate("s1", "B2", 5).value, 15)  # 30/2 exact
        self.h.formula("s1", "B3", "=AVG(A1:A3)", 6)
        self.assertEqual(self.h.evaluate("s1", "B3", 7).value, 20)  # 60/3 exact
        self.h.cell("s1", "A4", 7, 8)
        self.h.formula("s1", "B9", "=AVG(A3:A4)", 9)
        self.assertEqual(self.h.evaluate("s1", "B9", 10).value, (37, 2))  # 37/2 exact rational

    def test_min_max_count(self):
        self.h.formula("s1", "B4", "=MIN(A1:A3)", 4)
        self.assertEqual(self.h.evaluate("s1", "B4", 5).value, 10)
        self.h.formula("s1", "B5", "=MAX(A1:A3)", 6)
        self.assertEqual(self.h.evaluate("s1", "B5", 7).value, 30)
        self.h.formula("s1", "B6", "=COUNT(A1:A3)", 8)
        self.assertEqual(self.h.evaluate("s1", "B6", 9).value, 3)

    def test_blanks_count_as_zero(self):
        self.h.formula("s1", "B7", "=SUM(A1:A5)", 4)
        self.assertEqual(self.h.evaluate("s1", "B7", 5).value, 60)

    def test_formula_refusals(self):
        with self.assertRaises(FormulaError):
            self.h.formula("s1", "B1", "SUM(A1:A3)", 4)     # missing =
        with self.assertRaises(FormulaError):
            self.h.formula("s1", "B1", "=FOO(A1:A2)", 4)   # unknown fn
        with self.assertRaises(FormulaError):
            self.h.formula("s1", "B1", "=SUM()", 4)         # bad shape
        with self.assertRaises(FormulaError):
            self.h.formula("s1", "B1", "=SUM(B1:A2)", 4)    # self-ref
        self.h.formula("s1", "B8", "=SUM(A1:A2)", 4)
        with self.assertRaises(ValidationError):
            self.h.cell("s1", "B8", 5, 5)                  # formula holds it


class TestEvalErrors(unittest.TestCase):
    def test_string_in_range_is_fail_closed(self):
        h = ExcelHandler()
        h.create_sheet("s1", "Budget", 0)
        h.cell("s1", "A1", "text", 1)
        h.formula("s1", "B1", "=SUM(A1:A1)", 2)
        with self.assertRaises(EvalError):
            h.evaluate("s1", "B1", 3)

    def test_evaluate_without_formula(self):
        h = ExcelHandler()
        h.create_sheet("s1", "Budget", 0)
        with self.assertRaises(EvalError):
            h.evaluate("s1", "B9", 1)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        ev = excel_handler_audit_event("cell-set", 3,
                                       {"sheet_id": "s1", "ref": "A1"})
        self.assertEqual(ev["schema"], SCHEMA_PIN)
        self.assertEqual(ev["version"], EXCEL_HANDLER_VERSION)
        self.assertEqual(ev["kind"], "cell-set")
        with self.assertRaises(ValidationError):
            excel_handler_audit_event("bogus", 3, {})

    def test_main_self_check(self):
        excel_handler.main()


if __name__ == "__main__":
    unittest.main()
