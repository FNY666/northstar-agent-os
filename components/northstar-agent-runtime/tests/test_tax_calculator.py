"""Tests for tax_calculator.py (fifteenth-module batch, batch 22)."""

import unittest

import support  # noqa: F401

from tax_calculator import (
    AUDIT_SCHEMA,
    SCHEMA_PIN,
    TAX_CALCULATOR_VERSION,
    NoRateError,
    TaxCalculator,
    TaxConfigError,
)


def make_calc() -> TaxCalculator:
    calc = TaxCalculator()
    calc.add_rate("DE", "vat", 1900, 1, label="Germany standard VAT")
    calc.add_rate("DE", "vat", 700, 2, category="reduced", label="food")
    calc.add_rate("US-CA", "sales", 725, 3, label="California sales tax")
    return calc


class TestRates(unittest.TestCase):
    def test_add_rate_registers_and_gets(self):
        calc = TaxCalculator()
        rate = calc.add_rate("GB", "vat", 2000, 1)
        self.assertEqual(rate.jurisdiction, "GB")
        self.assertEqual(rate.tax_kind, "vat")
        self.assertEqual(rate.rate_bps, 2000)
        self.assertEqual(rate.version, TAX_CALCULATOR_VERSION)
        self.assertEqual(rate.schema, SCHEMA_PIN)
        fetched = calc.get_rate("GB")
        self.assertEqual(fetched.digest(), rate.digest())

    def test_add_rate_rejects_out_of_range(self):
        calc = TaxCalculator()
        with self.assertRaises(TaxConfigError):
            calc.add_rate("DE", "vat", 10001, 1)  # above 100%
        with self.assertRaises(TaxConfigError):
            calc.add_rate("DE", "vat", -1, 1)
        with self.assertRaises(TaxConfigError):
            calc.add_rate("DE", "excise", 500, 1)  # unknown kind
        with self.assertRaises(TaxConfigError):
            calc.add_rate("", "vat", 500, 1)  # empty jurisdiction

    def test_add_rate_replaces_same_category(self):
        calc = TaxCalculator()
        calc.add_rate("DE", "vat", 1900, 1)
        updated = calc.add_rate("DE", "vat", 2000, 2, label="new law")
        self.assertEqual(calc.get_rate("DE").rate_bps, 2000)
        self.assertEqual(updated.label, "new law")


class TestCalculate(unittest.TestCase):
    def test_calculate_standard_vat(self):
        calc = make_calc()
        q = calc.calculate(10000, "DE", 10)
        self.assertEqual(q.tax_cents, 1900)
        self.assertEqual(q.gross_cents, 11900)
        self.assertEqual(q.net_cents, 10000)
        self.assertEqual(q.rate_bps, 1900)
        self.assertFalse(q.vat_inclusive)
        self.assertFalse(q.exempt_applied)
        self.assertFalse(q.reverse_charge)
        self.assertTrue(q.digest().startswith("sha256:"))

    def test_calculate_reduced_category(self):
        calc = make_calc()
        q = calc.calculate(10000, "DE", 11, category="reduced")
        self.assertEqual(q.tax_cents, 700)
        self.assertEqual(q.gross_cents, 10700)
        self.assertEqual(q.category, "reduced")

    def test_calculate_sales_tax(self):
        calc = make_calc()
        q = calc.calculate(10000, "US-CA", 12)
        self.assertEqual(q.tax_kind, "sales")
        self.assertEqual(q.tax_cents, 725)
        self.assertEqual(q.gross_cents, 10725)

    def test_calculate_half_up_rounding(self):
        calc = TaxCalculator()
        calc.add_rate("FR", "vat", 2000, 1)  # 20%
        # 199 cents * 20% = 39.8 -> half-up -> 40
        q = calc.calculate(199, "FR", 2)
        self.assertEqual(q.tax_cents, 40)
        self.assertEqual(q.gross_cents, 239)

    def test_calculate_unknown_jurisdiction_fail_closed(self):
        calc = make_calc()
        with self.assertRaises(NoRateError):
            calc.calculate(10000, "XX", 13)
        with self.assertRaises(NoRateError):
            calc.calculate(10000, "DE", 13, category="luxury")

    def test_calculate_negative_amount_rejected(self):
        calc = make_calc()
        with self.assertRaises(TaxConfigError):
            calc.calculate(-100, "DE", 14)


class TestVatInclusive(unittest.TestCase):
    def test_vat_inclusive_extraction(self):
        calc = make_calc()
        # 11900 gross at 19% -> tax = 1900, net = 10000
        q = calc.calculate(11900, "DE", 15, vat_inclusive=True)
        self.assertTrue(q.vat_inclusive)
        self.assertEqual(q.tax_cents, 1900)
        self.assertEqual(q.net_cents, 10000)
        self.assertEqual(q.gross_cents, 11900)

    def test_vat_inclusive_requires_vat_kind(self):
        calc = make_calc()
        with self.assertRaises(TaxConfigError):
            calc.calculate(10725, "US-CA", 16, vat_inclusive=True)


class TestExemptions(unittest.TestCase):
    def test_exempt_grants_zero_rate(self):
        calc = make_calc()
        calc.exempt("vat-id-123", "DE", 20, reason="resale certificate")
        q = calc.calculate(10000, "DE", 21, entity_id="vat-id-123")
        self.assertEqual(q.tax_cents, 0)
        self.assertEqual(q.gross_cents, 10000)
        self.assertTrue(q.exempt_applied)

    def test_exempt_is_jurisdiction_scoped(self):
        calc = make_calc()
        calc.exempt("vat-id-123", "DE", 20)
        # same entity, different jurisdiction -> exemption not honored
        q = calc.calculate(10000, "US-CA", 21, entity_id="vat-id-123")
        self.assertEqual(q.tax_cents, 725)
        self.assertFalse(q.exempt_applied)

    def test_revoke_exemption_stops_applying(self):
        calc = make_calc()
        calc.exempt("vat-id-123", "DE", 20)
        calc.revoke_exemption("vat-id-123", "DE", 22)
        q = calc.calculate(10000, "DE", 23, entity_id="vat-id-123")
        self.assertEqual(q.tax_cents, 1900)
        self.assertFalse(q.exempt_applied)
        with self.assertRaises(NoRateError):
            calc.revoke_exemption("nobody", "DE", 24)

    def test_reverse_charge_quotes_zero_seller_tax(self):
        calc = make_calc()
        q = calc.calculate(10000, "DE", 25, reverse_charge=True)
        self.assertEqual(q.tax_cents, 0)
        self.assertTrue(q.reverse_charge)
        self.assertEqual(q.rate_bps, 1900)  # rate record still bound
        self.assertFalse(q.exempt_applied)

    def test_audit_trail_kinds_and_schema(self):
        calc = make_calc()
        calc.exempt("vat-id-1", "DE", 30)
        calc.revoke_exemption("vat-id-1", "DE", 31)
        calc.calculate(10000, "DE", 32)
        kinds = [e["kind"] for e in calc.events]
        self.assertEqual(
            kinds,
            [
                "tax_calculator.rate_added",
                "tax_calculator.rate_added",
                "tax_calculator.rate_added",
                "tax_calculator.exempted",
                "tax_calculator.exemption_revoked",
                "tax_calculator.calculated",
            ],
        )
        for event in calc.events:
            self.assertEqual(event["schema"], AUDIT_SCHEMA)
            self.assertEqual(event["module_version"], TAX_CALCULATOR_VERSION)
            self.assertTrue(event["digest"].startswith("sha256:"))


if __name__ == "__main__":
    unittest.main()
