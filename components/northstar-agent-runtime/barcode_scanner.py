"""Barcode / 2D-code scanner interface (QR / DataMatrix shaped, simulated).

Research motivation: agents constantly cross the physical-digital
boundary -- reading a QR-encoded WiFi credential, a DataMatrix on a
shipping label, an EAN-13 on a retail item -- and they also generate
codes the other way: a pairing QR on a setup screen, a payment-address
QR, a handoff token encoded for a camera to read. Both directions
reduce to the same bookkeeping shape:

- *generate*: a (format, payload) pair is admitted to the registry and
  pinned with a digest; the caller gets back a scan handle (``symbol``)
  that the host's camera pipeline feeds back into ``decode()``;
- *decode*: a host-reported scan claim is booked against the registry
  and the pinned payload is returned -- decoding is never a guess;
- *formats*: the pinned symbology vocabulary the runtime speaks.

This module is the *bookkeeping* half of that shape:

- ``BarcodeScanner`` -- owns the code registry. ``generate()``
  validates the payload against the format's rules (capacity caps,
  character sets, EAN/UPC check-digit derivation), records a frozen
  ``GeneratedCode`` and returns its scan handle; ``decode()`` books a
  scan of a known symbol and returns a frozen ``DecodedCode``;
  ``formats()`` lists the pinned vocabulary; ``code()`` /
  ``code_ids()`` / ``code_count()`` read back the ledger.
- ``barcode_scanner_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``generated`` / ``decoded`` / ``rejected``); ids, formats
  and digest pins only -- payloads never cross the audit boundary.

Fail-closed edges (fail loudly, never guess):

- ``format`` must be one of the pinned vocabulary (``qr``,
  ``datamatrix``, ``aztec``, ``pdf417``, ``code128``, ``code39``,
  ``ean13``, ``upca``); anything else raises ``UnknownFormatError``.
- Payloads are validated per format: capacity caps (QR 2953,
  DataMatrix 2335, Aztec 3832, PDF417 1850, Code128 80, Code39 43),
  Code128 is printable ASCII only, Code39 is the 43-character set
  only, EAN-13 takes exactly 12 digits and UPC-A exactly 11 digits
  with the check digit derived (never trusted from the caller).
  Violations raise ``BadPayloadError`` / ``PayloadTooLargeError``.
- ``ec_level`` is meaningful only for ``qr`` (``L``/``M``/``Q``/``H``,
  default ``M``); passing it for any other format raises
  ``BadOptionError``.
- ``decode()`` of an unknown scan handle raises
  ``UnknownSymbolError``; a ``format_hint`` that disagrees with the
  registered format raises ``FormatMismatchError``.
- Mutating calls consume strictly increasing caller-supplied int
  seqs (no wall-clock); rewinds raise ``SeqOrderError``. A failed
  mutation consumes its seq (fail-closed ledger position).

Honest scope:

- This module is simulated bookkeeping, not a computer-vision
  engine: it emits no pixels, parses no images, and cannot read a
  real camera frame. ``decode()`` books the host's scan claim
  against symbols this scanner issued; a foreign code the camera
  reads is outside this interface (it must be registered first).
- The payload digest pins what the *caller* supplied -- a lying host
  gets a lying ledger (GIGO boundary).
- Check-digit derivation is exact integer arithmetic over the
  caller's digits; the module never invents digits.
- In-memory only: pair with the durable audit writer if the scan
  history must survive a restart. ``main()`` self-checks the shape.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import hashlib as _hashlib
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return _hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
BARCODE_SCANNER_VERSION = "barcode-scanner.v1"

#: Schema pin carried by records and audit events.
BARCODE_SCANNER_SCHEMA = "northstar.barcode-scanner.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned symbology vocabulary.
QR = "qr"
DATAMATRIX = "datamatrix"
AZTEC = "aztec"
PDF417 = "pdf417"
CODE128 = "code128"
CODE39 = "code39"
EAN13 = "ean13"
UPCA = "upca"
FORMATS: Tuple[str, ...] = (
    QR, DATAMATRIX, AZTEC, PDF417, CODE128, CODE39, EAN13, UPCA,
)

#: Per-format payload capacity (characters), pinned to the real
#: symbology limits (byte-mode capacities for the 2D codes, practical
#: limits for the 1D codes; EAN-13/UPC-A take digits only and the
#: check digit is derived, so the caller supplies 12/11 digits).
_CAPACITY: Dict[str, int] = {
    QR: 2953,
    DATAMATRIX: 2335,
    AZTEC: 3832,
    PDF417: 1850,
    CODE128: 80,
    CODE39: 43,
    EAN13: 12,
    UPCA: 11,
}

#: QR error-correction levels (ISO/IEC 18004).
_EC_LEVELS = ("L", "M", "Q", "H")
_DEFAULT_EC = "M"

#: Code39's 43-character set.
_CODE39_RE = re.compile(r"[0-9A-Z .$/+%-]*")

#: ASCII digits only (str.isdigit accepts non-ASCII digits).
_DIGITS_RE = re.compile(r"[0-9]+")

#: Audit event kinds.
KIND_GENERATED = "generated"
KIND_DECODED = "decoded"
KIND_REJECTED = "rejected"
_KINDS = (KIND_GENERATED, KIND_DECODED, KIND_REJECTED)

#: Fields that must never cross the audit boundary (user content).
_BANNED_AUDIT_FIELDS = ("payload", "full_code", "raw_payload")


class BarcodeScannerError(Exception):
    """Base error for the barcode scanner."""


class UnknownFormatError(BarcodeScannerError):
    """The requested format is not in the pinned vocabulary."""


class BadPayloadError(BarcodeScannerError):
    """The payload violates the format's rules (type, charset, shape)."""


class PayloadTooLargeError(BadPayloadError):
    """The payload exceeds the format's pinned capacity."""


class BadOptionError(BarcodeScannerError):
    """An option (e.g. ec_level) is invalid for the chosen format."""


class SeqOrderError(BarcodeScannerError):
    """A caller seq is not a strictly increasing int (no wall-clock)."""


class UnknownSymbolError(BarcodeScannerError):
    """decode() was given a scan handle this scanner never issued."""


class UnknownCodeError(BarcodeScannerError):
    """A code id lookup missed the registry."""


class FormatMismatchError(BarcodeScannerError):
    """decode()'s format_hint disagrees with the registered format."""


def _check_seq(seq: Any, what: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise BarcodeScannerError(f"{what} must be an int >= 0 (not bool)")
    return seq


def _check_str(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise BarcodeScannerError(f"{what} must be a non-empty str")
    return value


def _pin(*parts: Any) -> str:
    return "sha256:" + jcs_sha256_hex(list(parts))


def _gtin_check_digit(digits: str) -> str:
    """Derive the EAN/UPC check digit over ASCII ``digits``.

    ``digits`` is 12 digits for EAN-13 or 11 digits for UPC-A; UPC-A
    is computed as EAN-13 with a leading zero (identical weights).
    Exact integer arithmetic -- no floats anywhere near the digits.
    """
    body = digits if len(digits) == 12 else "0" + digits
    total = 0
    for i, ch in enumerate(body):
        d = ord(ch) - 48  # ASCII digit, already validated
        total += d if i % 2 == 0 else 3 * d
    return str((10 - (total % 10)) % 10)


def _validate(format: str, payload: Any, ec_level: Any) -> Tuple[str, Optional[str]]:
    """Validate (format, payload, ec_level); return (full_code, resolved_ec)."""
    if not isinstance(format, str) or format not in _CAPACITY:
        raise UnknownFormatError(
            f"format must be one of {FORMATS}, got {format!r}"
        )
    if not isinstance(payload, str) or not payload:
        raise BadPayloadError("payload must be a non-empty str")

    full_code = payload
    if format == CODE128:
        if not payload.isascii() or any(not 32 <= ord(c) < 127 for c in payload):
            raise BadPayloadError("code128 payload must be printable ASCII")
    elif format == CODE39:
        if _CODE39_RE.fullmatch(payload) is None:
            raise BadPayloadError(
                "code39 payload must use the 43-character set [0-9A-Z .$/+%-]"
            )
    elif format in (EAN13, UPCA):
        want = _CAPACITY[format]
        if len(payload) != want or _DIGITS_RE.fullmatch(payload) is None:
            raise BadPayloadError(
                f"{format} payload must be exactly {want} ASCII digits"
            )
        full_code = payload + _gtin_check_digit(payload)

    if len(payload) > _CAPACITY[format]:
        raise PayloadTooLargeError(
            f"{format} payload exceeds capacity {_CAPACITY[format]} chars"
        )

    if format == QR:
        if ec_level is None:
            resolved: Optional[str] = _DEFAULT_EC
        elif ec_level in _EC_LEVELS:
            resolved = ec_level
        else:
            raise BadOptionError(
                f"qr ec_level must be one of {_EC_LEVELS}, got {ec_level!r}"
            )
    elif ec_level is not None:
        raise BadOptionError(f"ec_level is only meaningful for qr, not {format}")
    else:
        resolved = None
    return full_code, resolved


@dataclass(frozen=True)
class GeneratedCode:
    """One generated symbol, digest-pinned."""

    code_id: str
    format: str
    payload: str
    full_code: str  # payload + derived check digit for ean13/upca; else payload
    ec_level: Optional[str]
    seq: int
    digest: str
    symbol: str  # scan handle the host feeds back into decode()
    version: str = BARCODE_SCANNER_VERSION
    schema: str = BARCODE_SCANNER_SCHEMA


@dataclass(frozen=True)
class DecodedCode:
    """One booked scan claim, digest-pinned."""

    code_id: str
    format: str
    payload: str
    full_code: str
    seq: int
    digest: str
    version: str = BARCODE_SCANNER_VERSION
    schema: str = BARCODE_SCANNER_SCHEMA


class BarcodeScanner:
    """Deterministic single-host barcode generate/decode bookkeeping."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._codes: Dict[str, GeneratedCode] = {}   # code_id -> record
        self._symbols: Dict[str, str] = {}           # symbol -> code_id
        self._order: List[str] = []                  # generation order
        self._next_code = 0
        self._last_seq = -1

    # -- internal ---------------------------------------------------

    def _consume_seq(self, seq: int) -> None:
        _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} is not strictly greater than last seq {self._last_seq}"
            )
        self._last_seq = seq

    # -- vocabulary -------------------------------------------------

    def formats(self) -> Tuple[str, ...]:
        """The pinned symbology vocabulary."""
        return FORMATS

    # -- generate / decode ------------------------------------------

    def generate(
        self,
        format: str,
        payload: str,
        seq: int,
        *,
        ec_level: Optional[str] = None,
    ) -> GeneratedCode:
        """Admit a (format, payload) pair and return its scan handle."""
        full_code, resolved_ec = _validate(format, payload, ec_level)
        with self._lock:
            self._consume_seq(seq)
            self._next_code += 1
            code_id = f"bc-{self._next_code}"
            digest = _pin(["generate", code_id, format, payload,
                           resolved_ec, seq])
            symbol = "sym-" + jcs_sha256_hex(["symbol", digest])[:16]
            record = GeneratedCode(
                code_id=code_id,
                format=format,
                payload=payload,
                full_code=full_code,
                ec_level=resolved_ec,
                seq=seq,
                digest=digest,
                symbol=symbol,
            )
            self._codes[code_id] = record
            self._symbols[symbol] = code_id
            self._order.append(code_id)
            return record

    def decode(
        self,
        symbol: str,
        seq: int,
        *,
        format_hint: Optional[str] = None,
    ) -> DecodedCode:
        """Book a scan claim for a known symbol; never guess a payload."""
        _check_str(symbol, "symbol")
        if format_hint is not None and (
            not isinstance(format_hint, str) or format_hint not in _CAPACITY
        ):
            raise UnknownFormatError(
                f"format_hint must be one of {FORMATS}, got {format_hint!r}"
            )
        with self._lock:
            self._consume_seq(seq)
            code_id = self._symbols.get(symbol)
            if code_id is None:
                raise UnknownSymbolError(
                    f"unknown scan handle {symbol!r}: this scanner never issued it"
                )
            record = self._codes[code_id]
            if format_hint is not None and format_hint != record.format:
                raise FormatMismatchError(
                    f"format_hint {format_hint!r} disagrees with "
                    f"registered format {record.format!r}"
                )
            digest = _pin(["decode", code_id, symbol, seq])
            return DecodedCode(
                code_id=code_id,
                format=record.format,
                payload=record.payload,
                full_code=record.full_code,
                seq=seq,
                digest=digest,
            )

    # -- views ------------------------------------------------------

    def code(self, code_id: str) -> GeneratedCode:
        """A generated code, by id."""
        _check_str(code_id, "code_id")
        with self._lock:
            record = self._codes.get(code_id)
            if record is None:
                raise UnknownCodeError(f"unknown code {code_id!r}")
            return record

    def code_ids(self) -> Tuple[str, ...]:
        """All generated code ids, in generation order."""
        with self._lock:
            return tuple(self._order)

    def code_count(self) -> int:
        """How many codes have been generated."""
        with self._lock:
            return len(self._order)


def barcode_scanner_audit_event(
    kind: str, seq: int, **fields: Any
) -> "dict[str, Any]":
    """Shape an ``audit.ndjson/1`` record for a barcode-scanner event."""
    if kind not in _KINDS:
        raise BarcodeScannerError(f"unknown audit kind {kind!r}")
    _check_seq(seq)
    for key in _BANNED_AUDIT_FIELDS:
        if key in fields:
            raise BarcodeScannerError(
                f"field {key!r} must not cross the audit boundary"
            )
    event = {
        "kind": kind,
        "seq": seq,
        "schema": AUDIT_SCHEMA,
        "module": BARCODE_SCANNER_SCHEMA,
    }
    event.update({k: v for k, v in fields.items()})
    return event


def main() -> None:
    bs = BarcodeScanner()
    g = bs.generate("qr", "northstar://pair?session=7f3a", 1)
    assert g.code_id == "bc-1" and g.ec_level == "M"
    assert g.symbol.startswith("sym-")
    d = bs.decode(g.symbol, 2)
    assert d.payload == g.payload and d.format == "qr"
    # Well-known EAN-13 / UPC-A check-digit examples.
    e = bs.generate("ean13", "590123412345", 3)
    assert e.full_code == "5901234123457", e.full_code
    u = bs.generate("upca", "03600029145", 4)
    assert u.full_code == "036000291452", u.full_code
    # Fail-closed edges.
    try:
        bs.generate("qr", "", 5)
    except BadPayloadError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected BadPayloadError")
    try:
        bs.generate("upca", "123", 6)
    except BadPayloadError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected BadPayloadError")
    try:
        bs.decode("sym-0000000000000000", 7)
    except UnknownSymbolError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected UnknownSymbolError")
    barcode_scanner_audit_event(
        KIND_DECODED, 8, code_id=d.code_id, format=d.format, symbol=d.code_id
    )
    print("barcode-scanner OK: generate, decode, ean13/upca check digits, "
          "refusals, audit")


if __name__ == "__main__":
    main()
