"""Golden vectors for the JCS (RFC 8785) canonicalizer — ninety-fifth batch.

Every vector here is transcribed from the published RFC 8785 text
(checked 2026-10-04 at https://www.rfc-editor.org/rfc/rfc8785), with the
section cited. If any of these fail, the implementation is wrong — not
the vectors. The one exception is the cyberphone sample, a long-standing
community JCS sample that cross-checks our escaping against an
independent implementation.

Scope note: these pin the *canonicalizer*. They do not pin digests or
signatures made over it — those live in their own modules' tests.
"""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canonical_json import (  # noqa: E402
    JcsError,
    jcs_canonical_json,
    jcs_dumps,
    jcs_sha256_hex,
)


def _f(hex_bits: str) -> float:
    """IEEE 754 double from big-endian hex (RFC 8785 Appendix B, Table 1)."""
    return struct.unpack(">d", bytes.fromhex(hex_bits))[0]


class Rfc8785AppendixBTests(unittest.TestCase):
    """RFC 8785 Appendix B, Table 1: ECMAScript number serialization samples.

    Transcribed verbatim: (IEEE 754 hex, expected JSON representation).
    """

    VECTORS = [
        ("0000000000000000", "0"),  # Zero
        ("8000000000000000", "0"),  # Minus zero -> 0 (JCS forbids -0)
        ("0000000000000001", "5e-324"),  # Min pos number
        ("8000000000000001", "-5e-324"),  # Min neg number
        ("7fefffffffffffff", "1.7976931348623157e+308"),  # Max pos number
        ("ffefffffffffffff", "-1.7976931348623157e+308"),  # Max neg number
        ("4340000000000000", "9007199254740992"),  # Max pos int (2**53)
        ("c340000000000000", "-9007199254740992"),  # Max neg int
        ("4430000000000000", "295147905179352830000"),  # ~2**68
        ("44b52d02c7e14af5", "9.999999999999997e+22"),
        ("44b52d02c7e14af6", "1e+23"),
        ("44b52d02c7e14af7", "1.0000000000000001e+23"),
        ("444b1ae4d6e2ef4e", "999999999999999700000"),
        ("444b1ae4d6e2ef4f", "999999999999999900000"),
        ("444b1ae4d6e2ef50", "1e+21"),
        ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
        ("3eb0c6f7a0b5ed8d", "0.000001"),
        ("41b3de4355555553", "333333333.3333332"),
        ("41b3de4355555554", "333333333.33333325"),
        ("41b3de4355555555", "333333333.3333333"),
        ("41b3de4355555556", "333333333.3333334"),
        ("41b3de4355555557", "333333333.33333343"),
        ("becbf647612f3696", "-0.0000033333333333333333"),
        ("43143ff3c1cb0959", "1424953923781206.2"),  # Round to even (note 4)
    ]

    def test_appendix_b_table_1(self):
        for hex_bits, expected in self.VECTORS:
            with self.subTest(hex=hex_bits):
                self.assertEqual(jcs_dumps(_f(hex_bits)), expected)

    def test_nan_and_infinity_terminate(self):
        # Appendix B notes (3): "Values out of range are not permitted in
        # JSON" — a compliant implementation terminates with an error.
        for bad in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(JcsError, msg=repr(bad)):
                jcs_dumps(bad)
            with self.assertRaises(JcsError, msg=repr(bad)):
                jcs_dumps({"n": bad})

    def test_python_ints(self):
        # Safe-range ints emit bare; outside the range they go through the
        # IEEE 754 double path (Appendix B note (2): no extended precision).
        self.assertEqual(jcs_dumps(42), "42")
        self.assertEqual(jcs_dumps(-9007199254740991), "-9007199254740991")
        self.assertEqual(jcs_dumps(9007199254740991), "9007199254740991")
        self.assertEqual(jcs_dumps(2**53), "9007199254740992")
        self.assertEqual(jcs_dumps(2**68), "295147905179352830000")
        self.assertEqual(jcs_dumps(True), "true")  # bool before int


class Rfc8785StringTests(unittest.TestCase):
    """RFC 8785 §3.2.2.3: string serialization."""

    def test_short_escapes_mandatory(self):
        # §3.2.2.3: U+0008/U+0009/U+000A/U+000C/U+000D MUST be \b \t \n
        # \f \r — never \uhhhh.
        self.assertEqual(jcs_dumps("\b\t\n\f\r"), r'"\b\t\n\f\r"')

    def test_other_controls_lowercase_u(self):
        # §3.2.2.3: remaining U+0000–U+001F use lowercase \uhhhh.
        self.assertEqual(jcs_dumps("\u0000\u001f"), r'"\u0000\u001f"')
        self.assertEqual(jcs_dumps("\u000f"), r'"\u000f"')  # not \u000F

    def test_quote_backslash_slash(self):
        # §3.2.2.3: " and \ escaped; / never escaped.
        self.assertEqual(jcs_dumps('a"b\\c/d'), r'"a\"b\\c/d"')

    def test_non_ascii_raw(self):
        # §3.2.2.3 + §3.2.4: non-ASCII emitted raw, output is UTF-8.
        self.assertEqual(jcs_canonical_json({"a": "é€"}), '{"a":"é€"}'.encode("utf-8"))

    def test_lone_surrogate_terminates(self):
        # §3.2.2.3 note: lone surrogates MUST terminate with an error —
        # they would silently break cross-implementation signatures.
        for lone in ("\ud800", "\udfff", "a\udc00b"):
            with self.assertRaises(JcsError, msg=repr(lone)):
                jcs_dumps(lone)
            with self.assertRaises(JcsError, msg=repr(lone)):
                jcs_dumps({lone: 1})


class Rfc8785SortingTests(unittest.TestCase):
    """RFC 8785 §3.2.3: lexicographic property sorting."""

    def test_ascii_sort_and_no_whitespace(self):
        # §3.1 (no whitespace) + §3.2.3 (recursive sort).
        self.assertEqual(
            jcs_canonical_json({"b": 2, "a": [1, 0.5], "c": "hi"}),
            b'{"a":[1,0.5],"b":2,"c":"hi"}',
        )

    def test_nested_objects_sorted(self):
        self.assertEqual(
            jcs_canonical_json({"z": {"b": 1, "a": 2}, "a": 0}),
            b'{"a":0,"z":{"a":2,"b":1}}',
        )

    def test_array_order_preserved(self):
        self.assertEqual(jcs_dumps([3, 1, 2]), "[3,1,2]")

    def test_utf16_code_unit_order(self):
        # §3.2.3: sort by UTF-16 code *units*. U+10000 is the surrogate
        # pair D800 DC00: it sorts BEFORE U+FFFF (single unit 0xFFFF)
        # although its code point is larger. Code-point sorting gets this
        # wrong — this is the normative JCS/legacy divergence.
        self.assertEqual(
            jcs_canonical_json({"\uffff": 1, "\U00010000": 2}),
            '{"\U00010000":2,"\uffff":1}'.encode("utf-8"),
        )

    def test_sort_on_raw_form(self):
        # §3.2.3: sorting applies to the raw (unescaped) property name —
        # a newline (U+000A) sorts as the control character, not as the
        # two characters '\' 'n'.
        self.assertEqual(
            jcs_canonical_json({"b\n": 1, "aa": 2}),
            b'{"aa":2,"b\\n":1}',
        )


class CommunitySampleTests(unittest.TestCase):
    """Cross-implementation check: the long-standing cyberphone JCS sample."""

    def test_cyberphone_sample(self):
        inp = {
            "numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 1e-27],
            "string": "€$\u000f\nA'B\"\\\\\"/",
            "literals": [None, True, False],
        }
        self.assertEqual(
            jcs_canonical_json(inp),
            b'{"literals":[null,true,false],'
            b'"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
            b'"string":"\xe2\x82\xac$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}',
        )


class AdversarialInputTests(unittest.TestCase):
    """Fail-closed behavior on hostile or malformed input."""

    def test_minus_zero_is_zero(self):
        self.assertEqual(jcs_dumps(-0.0), "0")
        self.assertEqual(jcs_canonical_json({"n": -0.0}), b'{"n":0}')

    def test_huge_float_is_infinity_rejected(self):
        # 1e400 parses to inf in Python — JCS must reject, not emit.
        with self.assertRaises(JcsError):
            jcs_dumps(float("1e400"))

    def test_unsupported_types_rejected(self):
        for bad in (b"bytes", {1, 2}, object(), (x for x in ())):
            with self.assertRaises(JcsError, msg=type(bad).__name__):
                jcs_dumps(bad)

    def test_non_string_keys_rejected(self):
        with self.assertRaises(JcsError):
            jcs_dumps({1: "x"})

    def test_deterministic(self):
        obj = {"z": [3, {"b": "\n", "a": 1e21}], "a": None}
        self.assertEqual(jcs_canonical_json(obj), jcs_canonical_json(obj))

    def test_sha256_convenience(self):
        import hashlib

        obj = {"b": 1, "a": 2}
        self.assertEqual(
            jcs_sha256_hex(obj), hashlib.sha256(b'{"a":2,"b":1}').hexdigest()
        )


class DelegationIntegrityTests(unittest.TestCase):
    """The single-implementation invariant: every historic entry point
    funnels through canonical_json."""

    def test_audit_chain_delegates(self):
        from audit_chain import jcs_canonical_json as ac_jcs

        vectors = [
            {"b": 1, "a": "x\ny\t\b"},
            {"n": 1e21, "u": "\U00010000", "l": [1.5, None, True]},
            {},
            {"empty": {"nested": []}},
        ]
        for v in vectors:
            with self.subTest(v=v):
                self.assertEqual(ac_jcs(v), jcs_canonical_json(v))

    def test_static_verify_definition_digest_is_jcs(self):
        # definition_digest() must be SHA-256 over JCS bytes of the
        # canonical definition triple — byte-identical, not "equivalent".
        from static_verify import definition_digest

        definition = {
            "name": "read_file",
            "description": "reads\na file",
            "params": [{"name": "p", "type": "string", "required": True}],
            "required_caps": ["fs.read"],
        }
        canonical = {
            "name": "read_file",
            "description": "reads\na file",
            "params": [
                {"name": "p", "type": "string", "required": True, "enum": None}
            ],
            "required_caps": ["fs.read"],
        }
        self.assertEqual(definition_digest(definition), jcs_sha256_hex(canonical))

    def test_passport_envelope_is_jcs(self):
        # Passport signatures are Ed25519 over JCS bytes of the envelope.
        import hashlib

        from canonical_json import jcs_canonical_json as pjcs

        envelope = {"jti": "abc", "caps": ["a"], "exp": 123}
        # The passport module must import the JCS canonicalizer, not the
        # legacy audit_chain.canonical_json.
        import passport as passport_mod

        self.assertIs(passport_mod.canonical_json, pjcs)
        self.assertEqual(
            hashlib.sha256(passport_mod.canonical_json(envelope)).hexdigest(),
            jcs_sha256_hex(envelope),
        )


if __name__ == "__main__":
    unittest.main()
