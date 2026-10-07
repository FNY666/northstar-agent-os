"""Currency converter interface: FX rate table with exact-rational conversion.

Research note: a *currency converter* sits between an agent's money path and
the FX market. Real-world FX quotes (ECB reference rates, trading-desk
streams) share three properties that matter for a correct interface:
(1) *quotes are decimals, not floats* — a desk quoting EUR/USD 0.92 means
exactly 92/100, never the nearest IEEE double; (2) *quotes expire* — desks
reject trades on stale quotes (ECB refreshes daily; streaming desks refresh
in milliseconds); (3) *minor units differ per currency* — JPY has no minor
unit, USD/EUR have 2, BHD/JOD/KWD have 3 (ISO 4217).

The load-bearing invariants of this module are:

* **Exact rational math** — rates are stored as :class:`Fraction`. Callers
  pass rates as decimal strings (``"0.92"``), ints, or Fractions; *floats are
  refused fail-closed*, so no IEEE contamination ever enters the money path
  (the batch-5 JCS float-loss caveat applies to quotes too).
* **Base-anchored table** — every rate is quoted against one base currency
  (default USD); cross rates are derived by triangulation, so the table is
  internally arbitrage-free by construction (no triangular inconsistency).
* **Minor-unit money** — amounts are ints in the currency's minor units;
  per-currency ISO 4217 exponents are honored on both legs of a conversion.
* **Half-even rounding** — the final minor-unit result is round-half-even
  (banker's rounding, the finance standard), applied once, on the exact
  rational, never on an intermediate float.
* **Staleness bound** — rates carry caller-supplied seqs; a converter built
  with ``max_stale_seqs`` fails closed on quotes older than the bound
  relative to the newest rate data (FX-desk "never trade a stale quote").

House style: frozen dataclasses, caller-supplied int seqs (strictly
increasing across all ops, no wall-clock, no RNG), RLock-guarded,
fail-closed (bool/float amounts, bad ISO codes, non-positive or malformed
rates, unknown currencies, stale quotes, non-increasing seqs all raise a
subclass of :class:`CurrencyError`), stdlib-only, digest-pinned
:class:`RateRecord`, audit events shaped for ``audit.ndjson/1``
(ids + digest pins only — never amounts or rates), ``main()`` self-check.

Honest scope: this is a *quoting interface*, not an FX feed. ``set_rate()``
pins what the host *reported*; it cannot verify the rate against a real
market, detect a manipulated feed, or guarantee the quote is still live —
a host that lies gets a consistent ledger of lies (GIGO, same boundary as
every other bookkeeping module). For live rates pair with an attested feed
(``remote_attestation`` for the host) and re-set rates on every refresh.

Version pin: currency-converter.v1
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass, field
from fractions import Fraction
from typing import Dict, Mapping, Optional

VERSION = "currency-converter.v1"
SCHEMA = "northstar.currency-converter.v1"

__all__ = [
    "VERSION",
    "SCHEMA",
    "CurrencyError",
    "InvalidCurrencyError",
    "UnknownCurrencyError",
    "InvalidRateError",
    "InvalidAmountError",
    "StaleRateError",
    "SequenceError",
    "RateRecord",
    "CurrencyConverter",
    "MINOR_UNITS",
    "CURRENCY_SYMBOLS",
    "currency_converter_audit_event",
]


class CurrencyError(Exception):
    """Base for all currency-converter errors (fail-closed taxonomy)."""


class InvalidCurrencyError(CurrencyError):
    """Currency code is not a 3-letter alphabetic ISO code."""


class UnknownCurrencyError(CurrencyError):
    """Currency has no rate in the table (and is not the base)."""


class InvalidRateError(CurrencyError):
    """Rate is malformed, non-positive, or a float (IEEE refused)."""


class InvalidAmountError(CurrencyError):
    """Amount is not a non-negative int in minor units (floats refused)."""


class StaleRateError(CurrencyError):
    """A conversion leg's quote is older than the converter's staleness bound."""


class SequenceError(CurrencyError):
    """Caller-supplied seq did not strictly increase."""


# ---------------------------------------------------------------------------
# ISO 4217 minor-unit exponents (subset; anything not listed defaults to 2)
# ---------------------------------------------------------------------------

_MINOR_ZERO = (
    "BIF", "CLP", "DJF", "GNF", "ISK", "JPY", "KMF", "KRW",
    "PYG", "RWF", "UGX", "UYI", "VND", "VUV", "XAF", "XOF", "XPF",
)
_MINOR_THREE = ("BHD", "IQD", "JOD", "KWD", "LYD", "OMR", "TND")

MINOR_UNITS: Mapping[str, int] = {c: 0 for c in _MINOR_ZERO}
MINOR_UNITS = {**MINOR_UNITS, **{c: 3 for c in _MINOR_THREE}}

CURRENCY_SYMBOLS: Mapping[str, str] = {
    "USD": "$", "EUR": "\u20ac", "GBP": "\u00a3", "JPY": "\u00a5",
    "CNY": "\u00a5", "KRW": "\u20a9", "INR": "\u20b9", "RUB": "\u20bd",
    "CHF": "CHF ", "CAD": "CA$", "AUD": "A$", "NZD": "NZ$",
    "HKD": "HK$", "SGD": "S$", "MXN": "MX$", "BRL": "R$",
    "SEK": "kr ", "NOK": "kr ", "DKK": "kr ", "PLN": "z\u0142 ",
    "TRY": "\u20ba", "ZAR": "R ", "THB": "\u0e3f", "PHP": "\u20b1",
    "ILS": "\u20aa", "AED": "د.إ ", "SAR": "﷼ ",
}

_RATE_STR_RE = re.compile(r"^[0-9]+(\.[0-9]+)?$")


# ---------------------------------------------------------------------------
# canonical helpers
# ---------------------------------------------------------------------------

def _check_seq(seq: object) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SequenceError(f"seq must be a non-negative int, got {seq!r}")
    return seq


def _check_currency(currency: object) -> str:
    if not isinstance(currency, str) or len(currency) != 3 or not currency.isalpha():
        raise InvalidCurrencyError(
            f"currency must be a 3-letter ISO code, got {currency!r}")
    return currency.upper()


def _check_amount(amount: object) -> int:
    """Money is always a non-negative int in minor units. Floats refused."""
    if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
        raise InvalidAmountError(
            f"amount must be a non-negative int (minor units), got {amount!r}")
    if amount >= 2**53:
        raise InvalidAmountError(f"amount magnitude >= 2**53 refused: {amount!r}")
    return amount


def _parse_rate(rate: object) -> Fraction:
    """Parse a rate into an exact Fraction. Floats are refused fail-closed."""
    if isinstance(rate, bool):
        raise InvalidRateError(f"rate must not be bool, got {rate!r}")
    if isinstance(rate, float):
        raise InvalidRateError(
            f"floats refused in rate path (IEEE contamination): {rate!r}; "
            "pass a decimal string like '0.92'")
    if isinstance(rate, Fraction):
        frac = rate
    elif isinstance(rate, int):
        frac = Fraction(rate, 1)
    elif isinstance(rate, str):
        text = rate.strip()
        if not _RATE_STR_RE.match(text):
            raise InvalidRateError(
                f"rate string must be a non-negative decimal like '0.92', "
                f"got {rate!r}")
        frac = Fraction(text)  # Fraction(str) parses decimal strings exactly
    else:
        raise InvalidRateError(
            f"rate must be str, int, or Fraction, got {type(rate).__name__}")
    if frac <= 0:
        raise InvalidRateError(f"rate must be positive, got {frac}")
    return frac


def _pin(*parts: object) -> str:
    body = "|".join(str(p) for p in parts)
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


def _round_half_even(frac: Fraction) -> int:
    """Round a non-negative Fraction to the nearest int, ties to even."""
    n, r = divmod(frac.numerator, frac.denominator)
    twice = 2 * r
    if twice > frac.denominator or (twice == frac.denominator and n % 2 == 1):
        n += 1
    return n


# ---------------------------------------------------------------------------
# frozen records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RateRecord:
    currency: str
    rate: str          # canonical "num/den" — units of currency per 1 base
    base: str
    seq: int           # caller-supplied source seq of this quote
    digest: str
    version: str = field(default=VERSION, compare=False)
    schema: str = field(default=SCHEMA, compare=False)

    def as_dict(self) -> Dict[str, object]:
        return {
            "currency": self.currency,
            "rate": self.rate,
            "base": self.base,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }

    def fraction(self) -> Fraction:
        num, den = self.rate.split("/")
        return Fraction(int(num), int(den))


# ---------------------------------------------------------------------------
# converter
# ---------------------------------------------------------------------------

class CurrencyConverter:
    """Base-anchored FX rate table with exact-rational conversion.

    ``base_currency`` is the anchor every rate is quoted against
    (``set_rate("EUR", "0.92")`` means 1 USD = 0.92 EUR when base is USD).
    ``max_stale_seqs`` optionally fails closed on quotes older than the
    bound relative to the newest rate data.
    """

    def __init__(
        self,
        base_currency: str = "USD",
        max_stale_seqs: Optional[int] = None,
    ):
        self._base = _check_currency(base_currency)
        if max_stale_seqs is not None:
            if (isinstance(max_stale_seqs, bool) or
                    not isinstance(max_stale_seqs, int) or max_stale_seqs < 0):
                raise CurrencyError(
                    f"max_stale_seqs must be a non-negative int or None, "
                    f"got {max_stale_seqs!r}")
        self._max_stale = max_stale_seqs
        self._lock = threading.RLock()
        self._rates: Dict[str, RateRecord] = {}
        self._last_seq = -1
        self._rate_waterline = -1  # seq of the newest rate data

    def _advance_seq(self, seq: int) -> None:
        if seq <= self._last_seq:
            raise SequenceError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})")
        self._last_seq = seq

    # -- rates -------------------------------------------------------------

    def set_rate(self, currency: str, rate: object, seq: int) -> RateRecord:
        """Pin a rate: units of ``currency`` per 1 unit of the base currency.

        ``rate`` is a decimal string (``"0.92"``), int, or Fraction.
        Floats are refused. Re-setting a currency supersedes the old quote.
        """
        currency = _check_currency(currency)
        seq = _check_seq(seq)
        if currency == self._base:
            raise InvalidRateError(
                f"cannot set an explicit rate for the base currency {self._base!r} "
                "(it is 1 by definition)")
        frac = _parse_rate(rate)
        with self._lock:
            self._advance_seq(seq)
            canonical = f"{frac.numerator}/{frac.denominator}"
            digest = _pin("rate", self._base, currency, canonical, seq)
            rec = RateRecord(currency=currency, rate=canonical,
                             base=self._base, seq=seq, digest=digest)
            self._rates[currency] = rec
            if seq > self._rate_waterline:
                self._rate_waterline = seq
            return rec

    def _leg_fraction(self, currency: str) -> Fraction:
        """Units of ``currency`` per 1 base unit (base itself is 1)."""
        if currency == self._base:
            return Fraction(1, 1)
        rec = self._rates.get(currency)
        if rec is None:
            raise UnknownCurrencyError(
                f"no rate for {currency!r} (base is {self._base})")
        return rec.fraction()

    def rate_record(self, currency: str) -> RateRecord:
        currency = _check_currency(currency)
        with self._lock:
            rec = self._rates.get(currency)
            if rec is None:
                raise UnknownCurrencyError(f"no rate for {currency!r}")
            return rec

    def rate(self, from_currency: str, to_currency: str) -> Fraction:
        """Exact pairwise rate: units of ``to`` per 1 unit of ``from``."""
        from_currency = _check_currency(from_currency)
        to_currency = _check_currency(to_currency)
        with self._lock:
            return self._leg_fraction(to_currency) / self._leg_fraction(from_currency)

    def currencies(self) -> tuple:
        """All quoted currencies plus the base, sorted."""
        with self._lock:
            return tuple(sorted([self._base, *self._rates.keys()]))

    # -- conversion --------------------------------------------------------

    def _check_fresh(self, currency: str) -> None:
        if self._max_stale is None or currency == self._base:
            return
        rec = self._rates[currency]  # presence already validated by caller
        if self._rate_waterline - rec.seq > self._max_stale:
            raise StaleRateError(
                f"quote for {currency} is stale "
                f"(quote seq {rec.seq}, newest rate data seq "
                f"{self._rate_waterline}, bound {self._max_stale})")

    def convert(
        self,
        amount: int,
        from_currency: str,
        to_currency: str,
        seq: int,
    ) -> int:
        """Convert ``amount`` (minor units of ``from_currency``) to minor
        units of ``to_currency``. Exact rational math; one half-even
        rounding to the target minor unit."""
        amount = _check_amount(amount)
        from_currency = _check_currency(from_currency)
        to_currency = _check_currency(to_currency)
        seq = _check_seq(seq)
        with self._lock:
            self._advance_seq(seq)
            # validate legs exist before the staleness check
            from_frac = self._leg_fraction(from_currency)
            to_frac = self._leg_fraction(to_currency)
            self._check_fresh(from_currency)
            self._check_fresh(to_currency)
            if from_currency == to_currency:
                return amount
            from_exp = MINOR_UNITS.get(from_currency, 2)
            to_exp = MINOR_UNITS.get(to_currency, 2)
            # amount * (to_frac / from_frac) * 10**to_exp / 10**from_exp
            exact = (Fraction(amount, 1) * to_frac * (10 ** to_exp)
                     / (from_frac * (10 ** from_exp)))
            return _round_half_even(exact)

    # -- formatting --------------------------------------------------------

    def format(self, amount: int, currency: str) -> str:
        """Render minor-unit ``amount`` as a grouped major-unit string,
        e.g. ``$1,234.56`` / ``¥150``. Unknown codes fall back to ISO."""
        amount = _check_amount(amount)
        currency = _check_currency(currency)
        exp = MINOR_UNITS.get(currency, 2)
        scale = 10 ** exp
        major, minor = divmod(amount, scale)
        grouped = f"{major:,}"
        if exp:
            body = f"{grouped}.{minor:0{exp}d}"
        else:
            body = grouped
        symbol = CURRENCY_SYMBOLS.get(currency)
        if symbol is None:
            return f"{body} {currency}"
        if symbol.endswith(" "):
            return f"{symbol}{body}"
        return f"{symbol}{body}"


# ---------------------------------------------------------------------------
# audit events
# ---------------------------------------------------------------------------

_AUDIT_KINDS = ("rate-set", "converted", "rejected")


def currency_converter_audit_event(
    kind: str, seq: int, currency: str = ""
) -> Dict[str, object]:
    """Shape an audit.ndjson/1 record. Only kind/seq/currency; never amounts
    or rates."""
    if kind not in _AUDIT_KINDS:
        raise CurrencyError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    if currency:
        _check_currency(currency)
    return {
        "kind": kind,
        "seq": seq,
        "currency": currency,
        "version": VERSION,
        "schema": SCHEMA,
    }


# ---------------------------------------------------------------------------
# self-check
# ---------------------------------------------------------------------------

def main() -> None:
    c = CurrencyConverter(base_currency="USD", max_stale_seqs=100)
    eur = c.set_rate("EUR", "0.92", seq=1)
    assert eur.fraction() == Fraction(92, 100)
    assert eur.digest.startswith("sha256:")
    c.set_rate("JPY", "149.50", seq=2)
    c.set_rate("BHD", "0.376", seq=3)
    assert c.convert(100, "USD", "EUR", seq=4) == 92
    assert c.convert(100, "USD", "USD", seq=5) == 100
    assert c.convert(100, "USD", "JPY", seq=6) == 150  # 149.5 -> half-even 150
    assert c.convert(100, "USD", "BHD", seq=7) == 376  # 1 USD = 0.376 BHD = 376 fils
    # cross-rate consistency: EUR->JPY equals triangulation via USD
    via = c.convert(c.convert(10000, "EUR", "USD", seq=8), "USD", "JPY", seq=9)
    direct = c.convert(10000, "EUR", "JPY", seq=10)
    assert abs(direct - via) <= 1, "triangulation must agree within 1 minor unit"
    assert c.format(123456, "USD") == "$1,234.56"
    assert c.format(150, "JPY") == "\u00a5150"
    assert c.format(38, "BHD") == "0.038 BHD"  # 3dp minor unit, ISO fallback
    try:
        c.set_rate("EUR", 0.92, seq=11)  # float refused
        raise AssertionError("float rate must fail")
    except InvalidRateError:
        pass
    try:
        c.convert(100, "USD", "XXX", seq=12)
        raise AssertionError("unknown currency must fail")
    except UnknownCurrencyError:
        pass
    ev = currency_converter_audit_event("converted", 13, currency="EUR")
    assert ev["schema"] == SCHEMA and "amount" not in ev and "rate" not in ev
    # staleness bound: quote seq 1 is 12 behind waterline 13... refresh first
    stale = CurrencyConverter(base_currency="USD", max_stale_seqs=2)
    stale.set_rate("EUR", "0.92", seq=1)
    stale.set_rate("JPY", "149.50", seq=10)  # waterline moves to 10
    try:
        stale.convert(100, "EUR", "USD", seq=11)
        raise AssertionError("stale quote must fail")
    except StaleRateError:
        pass
    assert stale.convert(100, "JPY", "USD", seq=12) >= 0  # fresh leg works
    print("currency-converter OK: rates, exact conversion, rounding, "
          "format, staleness, audit")


if __name__ == "__main__":
    main()
