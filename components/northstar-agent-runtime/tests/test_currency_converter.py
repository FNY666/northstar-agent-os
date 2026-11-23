"""Tests for currency_converter: FX rate table with exact-rational conversion."""

import unittest
from fractions import Fraction

from currency_converter import (
    VERSION,
    SCHEMA,
    CurrencyError,
    InvalidCurrencyError,
    UnknownCurrencyError,
    InvalidRateError,
    InvalidAmountError,
    StaleRateError,
    SequenceError,
    RateRecord,
    CurrencyConverter,
    currency_converter_audit_event,
    main,
)


def make(**kw) -> CurrencyConverter:
    return CurrencyConverter(base_currency="USD", **kw)


def quoted() -> CurrencyConverter:
    c = make()
    c.set_rate("EUR", "0.92", seq=1)
    c.set_rate("JPY", "149.50", seq=2)
    c.set_rate("BHD", "0.376", seq=3)
    return c


class TestPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(VERSION, "currency-converter.v1")
        self.assertEqual(SCHEMA, "northstar.currency-converter.v1")


class TestSetRate(unittest.TestCase):
    def test_set_rate_roundtrip(self):
        c = make()
        rec = c.set_rate("EUR", "0.92", seq=1)
        self.assertIsInstance(rec, RateRecord)
        self.assertEqual(rec.currency, "EUR")
        self.assertEqual(rec.fraction(), Fraction(92, 100))
        self.assertEqual(rec.base, "USD")
        self.assertEqual(rec.seq, 1)
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(rec.version, VERSION)
        self.assertEqual(rec.schema, SCHEMA)
        self.assertEqual(c.rate_record("EUR"), rec)

    def test_currency_code_normalized(self):
        c = make()
        rec = c.set_rate("eur", "0.92", seq=1)
        self.assertEqual(rec.currency, "EUR")

    def test_base_rate_is_one_by_definition(self):
        c = make()
        self.assertEqual(c.rate("USD", "USD"), Fraction(1, 1))
        self.assertEqual(c.convert(100, "USD", "USD", seq=1), 100)
        with self.assertRaises(InvalidRateError):
            c.set_rate("USD", "1", seq=2)  # base needs no explicit quote

    def test_float_rate_refused(self):
        c = make()
        for bad in (0.92, float("nan"), 1.0):
            with self.assertRaises(InvalidRateError):
                c.set_rate("EUR", bad, seq=1)  # type: ignore[arg-type]

    def test_bad_rates_refused(self):
        c = make()
        for bad in ("0", "-1.5", "abc", "", "1.2.3", True, None):
            with self.assertRaises((InvalidRateError, CurrencyError)):
                c.set_rate("EUR", bad, seq=1)  # type: ignore[arg-type]

    def test_int_and_fraction_rates_accepted(self):
        c = make()
        self.assertEqual(c.set_rate("EUR", 2, seq=1).fraction(), Fraction(2, 1))
        self.assertEqual(
            c.set_rate("GBP", Fraction(3, 4), seq=2).fraction(), Fraction(3, 4))

    def test_resubmission_supersedes(self):
        c = quoted()
        rec = c.set_rate("EUR", "0.95", seq=10)
        self.assertEqual(rec.fraction(), Fraction(95, 100))
        self.assertEqual(c.convert(100, "USD", "EUR", seq=11), 95)

    def test_bad_iso_code_refused(self):
        c = make()
        for bad in ("US", "USDD", "U1D", "", 123, None):
            with self.assertRaises(InvalidCurrencyError):
                c.set_rate(bad, "1.0", seq=1)  # type: ignore[arg-type]

    def test_seq_must_increase(self):
        c = quoted()
        with self.assertRaises(SequenceError):
            c.set_rate("CHF", "0.88", seq=3)  # not > last seq 3


class TestConvert(unittest.TestCase):
    def test_identity_conversion(self):
        c = quoted()
        self.assertEqual(c.convert(12345, "USD", "USD", seq=10), 12345)

    def test_exact_conversion(self):
        c = quoted()
        self.assertEqual(c.convert(100, "USD", "EUR", seq=10), 92)

    def test_half_even_rounding(self):
        c = quoted()
        # 100 USD cents = 1 USD -> 149.50 JPY; half-even: 149.5 -> 150
        self.assertEqual(c.convert(100, "USD", "JPY", seq=10), 150)
        # tie to even: 1 USD cent at 0.5 X/USD -> 0.5 minor -> rounds to 0 (even)
        d = make()
        d.set_rate("XXX", "0.5", seq=1)
        self.assertEqual(d.convert(1, "USD", "XXX", seq=2), 0)

    def test_subunit_exponents(self):
        c = quoted()
        # BHD has 3 minor digits: 1 USD -> 0.376 BHD = 376 fils
        self.assertEqual(c.convert(100, "USD", "BHD", seq=10), 376)
        # JPY has 0: no fractional yen in output
        r = c.convert(1, "USD", "JPY", seq=11)
        self.assertIsInstance(r, int)

    def test_cross_rate_triangulation(self):
        c = quoted()
        direct = c.rate("EUR", "JPY")
        self.assertEqual(direct, Fraction(14950, 100) / Fraction(92, 100))
        via = c.convert(c.convert(10000, "EUR", "USD", seq=10), "USD", "JPY", seq=11)
        self.assertLessEqual(abs(c.convert(10000, "EUR", "JPY", seq=12) - via), 1)

    def test_unknown_currency_raises(self):
        c = quoted()
        with self.assertRaises(UnknownCurrencyError):
            c.convert(100, "USD", "XXX", seq=10)
        with self.assertRaises(UnknownCurrencyError):
            c.convert(100, "XXX", "USD", seq=11)

    def test_bad_amounts_refused(self):
        c = quoted()
        for bad in (-1, 1.5, True, "100", None):
            with self.assertRaises(InvalidAmountError):
                c.convert(bad, "USD", "EUR", seq=10)  # type: ignore[arg-type]

    def test_convert_seq_must_increase(self):
        c = quoted()
        c.convert(100, "USD", "EUR", seq=10)
        with self.assertRaises(SequenceError):
            c.convert(100, "USD", "EUR", seq=10)

    def test_stale_quote_refused(self):
        c = make(max_stale_seqs=2)
        c.set_rate("EUR", "0.92", seq=1)
        c.set_rate("JPY", "149.50", seq=10)  # waterline -> 10; EUR 9 behind
        with self.assertRaises(StaleRateError):
            c.convert(100, "EUR", "USD", seq=11)
        # fresh leg still converts; base leg never goes stale
        self.assertGreaterEqual(c.convert(100, "JPY", "USD", seq=12), 0)
        self.assertEqual(c.convert(100, "USD", "USD", seq=13), 100)

    def test_no_staleness_bound_by_default(self):
        c = make()  # max_stale_seqs=None
        c.set_rate("EUR", "0.92", seq=1)
        c.set_rate("JPY", "149.50", seq=1000)
        self.assertEqual(c.convert(100, "EUR", "USD", seq=1001), 109)  # no bound


class TestFormat(unittest.TestCase):
    def test_format_usd(self):
        c = make()
        self.assertEqual(c.format(123456, "USD"), "$1,234.56")
        self.assertEqual(c.format(0, "USD"), "$0.00")

    def test_format_jpy_no_minor(self):
        c = make()
        self.assertEqual(c.format(150, "JPY"), "¥150")
        self.assertEqual(c.format(1000000, "JPY"), "¥1,000,000")

    def test_format_iso_fallback(self):
        c = make()
        self.assertEqual(c.format(376, "BHD"), "0.376 BHD")

    def test_format_bad_inputs_refused(self):
        c = make()
        with self.assertRaises(InvalidAmountError):
            c.format(-5, "USD")
        with self.assertRaises(InvalidCurrencyError):
            c.format(100, "US")


class TestAudit(unittest.TestCase):
    def test_audit_event_shape(self):
        ev = currency_converter_audit_event("converted", 7, currency="EUR")
        self.assertEqual(ev["kind"], "converted")
        self.assertEqual(ev["seq"], 7)
        self.assertEqual(ev["currency"], "EUR")
        self.assertEqual(ev["version"], VERSION)
        self.assertEqual(ev["schema"], SCHEMA)
        self.assertNotIn("amount", ev)
        self.assertNotIn("rate", ev)

    def test_audit_bad_kind_refused(self):
        with self.assertRaises(CurrencyError):
            currency_converter_audit_event("bogus", 1)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        main()  # must not raise


if __name__ == "__main__":
    unittest.main()
