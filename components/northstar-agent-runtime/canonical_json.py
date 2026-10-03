"""JSON Canonicalization Scheme (RFC 8785) — the single canonicalizer.

Every digest-pinned signature in Northstar (passport envelopes, definition
digests, audit-chain v2 anchors, trace-export identities) funnels through
this module. One implementation, written directly from the RFC 8785 text
(checked against the published RFC on 2026-10-04), pinned by golden test
vectors transcribed from the RFC's own examples.

Rules implemented, with RFC 8785 section cites:

- §3.1: no whitespace between tokens.
- §3.2.2.1: ``null`` / ``true`` / ``false`` literals.
- §3.2.2.2: numbers as IEEE 754 doubles serialized per ECMA-262
  ``Number.prototype.toString`` (shortest round-trip, ``-0`` forbidden and
  emitted as ``0``). NaN and Infinity are not JSON: they raise.
- §3.2.2.3: strings escape ``"`` and ``\\``; the five predefined controls
  U+0008/U+0009/U+000A/U+000C/U+000D as ``\\b \\t \\n \\f \\r``; every other
  U+0000–U+001F as lowercase ``\\uhhhh``; everything else raw (including
  non-ASCII — output is UTF-8, §3.2.4). Lone surrogates (U+D800–U+DFFF)
  terminate with an error per the §3.2.2.3 note: they would silently break
  cross-implementation signatures.
- §3.2.3: object properties sorted recursively by UTF-16 code *units*
  (big-endian comparison), not code points — astral characters sort by
  their high surrogate. Array element order is preserved.
- §3 (I-JSON input constraints): duplicate property names are rejected
  (Python dicts cannot hold them; a parsed duplicate is a caller bug, not
  a canonicalization question).

Relationship to the older code:

- ``audit_chain.canonical_json`` is the *legacy* chain-v1 canonicalization
  (kept byte-identical forever so v1 feeds keep verifying). It is close to
  JCS but sorts keys by code point. New code must use this module.
- ``audit_chain.jcs_canonical_json`` delegates here; the old copy of the
  algorithm that lived in ``audit_chain`` had a real spec bug (it emitted
  ``\\u000a`` for newline, contradicting RFC 8785 §3.2.2.3's mandatory
  short escapes) and is now retired in favor of this module.
- ``static_verify.canonical_json`` (the 91st batch's hand-rolled
  ``json.dumps``) now delegates here as well, so definition digests are
  JCS digests.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

__all__ = [
    "JcsError",
    "jcs_canonical_json",
    "jcs_dumps",
    "jcs_sha256_hex",
]


class JcsError(ValueError):
    """Input that JCS cannot canonicalize (lone surrogate, NaN/Infinity,
    unsupported type). Raised, never silently worked around: a signature
    over silently-mangled input is worse than no signature."""


# ---------------------------------------------------------------------------
# Strings — RFC 8785 §3.2.2.3
# ---------------------------------------------------------------------------

#: The five predefined JSON control characters and their mandatory short
#: escapes (RFC 8785 §3.2.2.3: U+0008→\b, U+0009→\t, U+000A→\n, U+000C→\f,
#: U+000D→\r). Everything else in U+0000–U+001F uses lowercase \uhhhh.
_SHORT_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
}


def _jcs_escape(text: str) -> str:
    """Escape a string body per RFC 8785 §3.2.2.3."""
    out: list[str] = []
    for char in text:
        code = ord(char)
        if char == '"':
            out.append('\\"')
        elif char == "\\":
            out.append("\\\\")
        elif 0xD800 <= code <= 0xDFFF:
            # RFC 8785 §3.2.2.3 note: lone surrogates "MUST cause a
            # compliant JCS implementation to terminate with an
            # appropriate error" — they break signatures silently.
            raise JcsError(f"lone surrogate U+{code:04X} is not JCS-serializable")
        elif code in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[code])
        elif code < 0x20:
            out.append("\\u%04x" % code)  # lowercase hex, per §3.2.2.3
        else:
            out.append(char)  # raw, including non-ASCII (§3.2.4 → UTF-8)
    return "".join(out)


# ---------------------------------------------------------------------------
# Numbers — RFC 8785 §3.2.2.2 via ECMA-262 Number.prototype.toString
# ---------------------------------------------------------------------------

#: JCS integer fast path range, RFC 8785 Appendix B note (1):
#: (-(2**53)+1) .. ((2**53)-1).
_SAFE_INT = 2**53

_NUMBER_RE = re.compile(r"(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?")


def _es_number_to_string(value: float) -> str:
    """ECMAScript ``Number.prototype.toString`` for a finite non-zero float.

    Python's ``repr`` already produces the shortest round-trip digit string
    (verified byte-identical against every sample in RFC 8785 Appendix B,
    Table 1); only the *formatting* differs from ECMAScript (exponent
    thresholds, exponent padding, no ``e+`` suppression), so the repr is
    decomposed into significant digits + decimal exponent and re-emitted
    under the ECMA-262 §7.1.12.1 layout rules.
    """
    if value == 0:
        # JCS forbids -0 (RFC 8785 §3.2.2.2 / Appendix B: 0x8000000000000000
        # serializes as "0"). Guarded here too: without it the digit-strip
        # loop below would spin forever on a zero digit string.
        return "0"
    rep = repr(value)
    negative = rep.startswith("-")
    if negative:
        rep = rep[1:]
    match = _NUMBER_RE.fullmatch(rep)
    if match is None:  # pragma: no cover — repr of a finite float always matches
        raise JcsError(f"cannot decompose float repr {rep!r}")
    int_part, frac_part, exp_part = match.group(1), match.group(2) or "", match.group(3)
    digits = int(int_part + frac_part)  # significant digits
    exp = (int(exp_part) if exp_part else 0) - len(frac_part)
    # ECMA-262 picks the decomposition with the smallest k: strip trailing
    # zeros (repr's ".0" on integral floats would otherwise add one).
    while digits % 10 == 0:
        digits //= 10
        exp += 1
    chars = str(digits)
    width = len(chars)
    point = exp + width  # ECMA-262's n: value = chars * 10**(point-width)
    if width <= point <= 21:
        body = chars + "0" * (point - width)
    elif 0 < point <= 21:
        body = chars[:point] + "." + chars[point:]
    elif -6 < point <= 0:
        body = "0." + "0" * (-point) + chars
    else:
        exp10 = point - 1
        body = (
            chars[0]
            + ("." + chars[1:] if width > 1 else "")
            + "e"
            + ("+" if exp10 >= 0 else "")
            + str(exp10)
        )
    return ("-" if negative else "") + body


# ---------------------------------------------------------------------------
# Key ordering — RFC 8785 §3.2.3
# ---------------------------------------------------------------------------


def _utf16_key(key: str) -> bytes:
    """Sort key for JCS object properties: UTF-16 code units, big-endian.

    RFC 8785 §3.2.3 sorts by UTF-16 code *unit*, not Unicode code point;
    the two orders agree inside the BMP but differ for astral characters
    (a surrogate pair sorts by its high surrogate, so U+10000 precedes
    U+FFFF). Comparing the big-endian UTF-16 byte sequences implements
    exactly that order.

    Lone surrogates are rejected with :class:`JcsError` here (not left to
    the codec's ``UnicodeEncodeError``) so key sorting fails the same
    clean way string escaping does.
    """
    for char in key:
        if 0xD800 <= ord(char) <= 0xDFFF:
            raise JcsError(f"lone surrogate U+{ord(char):04X} in property name")
    return key.encode("utf-16-be")


# ---------------------------------------------------------------------------
# Recursive serializer — RFC 8785 §3
# ---------------------------------------------------------------------------


def jcs_dumps(value: Any) -> str:
    """Serialize ``value`` to a JCS canonical string (RFC 8785 §3).

    Raises :class:`JcsError` for NaN/Infinity, lone surrogates, and types
    outside the JSON data model.
    """
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return '"' + _jcs_escape(value) + '"'
    if isinstance(value, int):
        if -_SAFE_INT < value < _SAFE_INT:
            return str(value)
        # Outside the safe-integer range JCS still serializes the IEEE 754
        # double (Appendix B note (2): no extended precision).
        return _es_number_to_string(float(value))
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise JcsError("JCS forbids NaN and Infinity (RFC 8785 §3.2.2.2)")
        return _es_number_to_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(jcs_dumps(item) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise JcsError(f"JCS object keys must be strings, got {type(key).__name__}")
        items = sorted(value.items(), key=lambda kv: _utf16_key(kv[0]))
        return (
            "{"
            + ",".join('"' + _jcs_escape(key) + '":' + jcs_dumps(item) for key, item in items)
            + "}"
        )
    raise JcsError(f"JCS cannot serialize {type(value).__name__}")


def jcs_canonical_json(obj: Any) -> bytes:
    """JSON Canonicalization Scheme (RFC 8785) bytes, UTF-8 (§3.2.4).

    The single canonicalization every signature and digest pin in
    Northstar must use. Deterministic: equal logical values always yield
    identical bytes.
    """
    return jcs_dumps(obj).encode("utf-8")


def jcs_sha256_hex(obj: Any) -> str:
    """SHA-256 hex digest over the JCS canonical bytes of ``obj``.

    Convenience for digest pinning (definition digests, content hashes).
    """
    return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()
