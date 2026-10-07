"""Tests for key_derivation.py (HKDF, RFC 5869, pinned to SHA-256)."""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from key_derivation import (
    HKDF,
    DerivedKey,
    KDFError,
    KEY_DERIVATION_SCHEMA,
    KEY_DERIVATION_VERSION,
    key_derivation_audit_event,
)


def _u16(path):
    with open(path, "rb") as f:
        return f.read()


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(KEY_DERIVATION_VERSION, "key-derivation.v1")

    def test_schema_pin(self):
        self.assertEqual(KEY_DERIVATION_SCHEMA, "northstar.key-derivation.v1")


class TestRfc5869Vectors(unittest.TestCase):
    """RFC 5869 Appendix A vectors, constants copied from the RFC text."""

    def test_case_1_prk(self):
        ikm = bytes.fromhex("0b" * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        prk = HKDF.extract(salt, ikm)
        self.assertEqual(
            prk,
            bytes.fromhex(
                "077709362c2e32df0ddc3f0dc47bba63"
                "90b6c73bb50f9c3122ec844ad7c2b3e5"
            ),
        )

    def test_case_1_okm(self):
        ikm = bytes.fromhex("0b" * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        okm = HKDF.expand(HKDF.extract(salt, ikm), info, 42)
        self.assertEqual(
            okm,
            bytes.fromhex(
                "3cb25f25faacd57a90434f64d0362f2a"
                "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                "34007208d5b887185865"
            ),
        )

    def test_case_3_empty_salt_info(self):
        # RFC 5869 A.3: zero-length salt/info, L=42.
        ikm = bytes.fromhex("0b" * 22)
        prk = HKDF.extract(b"", ikm)
        self.assertEqual(
            prk,
            bytes.fromhex(
                "19ef24a32c717b167f33a91d6f648bdf"
                "96596776afdb6377ac434c1c293ccb04"
            ),
        )
        okm = HKDF.expand(prk, b"", 42)
        self.assertEqual(
            okm,
            bytes.fromhex(
                "8da4e775a563c18f715f802a063c5a31"
                "b8a11f5c5ee1879ec3454e5f3c738d2d"
                "9d201395faa4b61a96c8"
            ),
        )

    def test_case_1_full_derive(self):
        ikm = bytes.fromhex("0b" * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        okm, record = HKDF().derive(ikm, info, 42, salt)
        self.assertEqual(len(okm), 42)
        self.assertEqual(
            okm,
            bytes.fromhex(
                "3cb25f25faacd57a90434f64d0362f2a"
                "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                "34007208d5b887185865"
            ),
        )
        self.assertEqual(record.length, 42)
        self.assertEqual(record.info, info)
        self.assertTrue(record.key_pin.startswith("sha256:"))


class TestExtractValidation(unittest.TestCase):
    def test_none_salt_defaults_to_zeros(self):
        ikm = b"\x0b" * 22
        prk = HKDF.extract(None, ikm)
        self.assertEqual(len(prk), 32)

    def test_ikm_type_rejected(self):
        with self.assertRaises(KDFError):
            HKDF.extract(b"salt", "not-bytes")

    def test_short_ikm_refused(self):
        with self.assertRaises(KDFError):
            HKDF.extract(b"salt", b"too-short")

    def test_empty_ikm_refused(self):
        with self.assertRaises(KDFError):
            HKDF.extract(b"salt", b"")

    def test_salt_type_rejected(self):
        with self.assertRaises(KDFError):
            HKDF.extract("not-bytes", b"\x0b" * 22)

    def test_deterministic(self):
        ikm = b"\x0b" * 22
        self.assertEqual(HKDF.extract(b"s", ikm), HKDF.extract(b"s", ikm))


class TestExpandValidation(unittest.TestCase):
    def setUp(self):
        self.prk = HKDF.extract(b"salt", b"\x0b" * 22)

    def test_wrong_prk_length(self):
        with self.assertRaises(KDFError):
            HKDF.expand(b"\x00" * 16, b"info", 32)

    def test_prk_type_rejected(self):
        with self.assertRaises(KDFError):
            HKDF.expand("not-bytes", b"info", 32)

    def test_length_zero_refused(self):
        with self.assertRaises(KDFError):
            HKDF.expand(self.prk, b"info", 0)

    def test_length_too_long_refused(self):
        with self.assertRaises(KDFError):
            HKDF.expand(self.prk, b"info", 255 * 32 + 1)

    def test_length_bool_refused(self):
        with self.assertRaises(KDFError):
            HKDF.expand(self.prk, b"info", True)

    def test_max_length(self):
        self.assertEqual(len(HKDF.expand(self.prk, b"info", 255 * 32)), 255 * 32)

    def test_info_type_rejected(self):
        with self.assertRaises(KDFError):
            HKDF.expand(self.prk, "not-bytes", 32)

    def test_info_domain_separation(self):
        a = HKDF.expand(self.prk, b"mcp-sign", 32)
        b = HKDF.expand(self.prk, b"audit-seal", 32)
        self.assertNotEqual(a, b)

    def test_salt_domain_separation(self):
        a = HKDF.extract(b"salt-a", b"\x0b" * 22)
        b = HKDF.extract(b"salt-b", b"\x0b" * 22)
        self.assertNotEqual(a, b)

    def test_multi_block_okm(self):
        okm = HKDF.expand(self.prk, b"info", 64)
        self.assertEqual(len(okm), 64)
        # Prefix property: first 32 bytes match the 32-byte derivation.
        self.assertEqual(okm[:32], HKDF.expand(self.prk, b"info", 32))

    def test_deterministic(self):
        self.assertEqual(
            HKDF.expand(self.prk, b"info", 42),
            HKDF.expand(self.prk, b"info", 42),
        )


class TestDerivedKeyRecord(unittest.TestCase):
    def _record(self):
        okm, record = HKDF().derive(b"\x0b" * 22, b"ctx", 32, b"salt")
        return okm, record

    def test_key_bytes_not_in_record(self):
        okm, record = self._record()
        blob = repr(record)
        self.assertNotIn(okm.hex(), blob)

    def test_frozen(self):
        _, record = self._record()
        with self.assertRaises(Exception):
            record.length = 16  # type: ignore

    def test_as_dict_shape(self):
        _, record = self._record()
        d = record.as_dict()
        self.assertEqual(d["length"], 32)
        self.assertEqual(d["version"], KEY_DERIVATION_VERSION)
        self.assertEqual(d["schema"], KEY_DERIVATION_SCHEMA)

    def test_bad_pin_rejected(self):
        with self.assertRaises(KDFError):
            DerivedKey(key_pin="md5:abc", info=b"i", length=32)


class TestAuditEvents(unittest.TestCase):
    def test_event_shape(self):
        _, record = HKDF().derive(b"\x0b" * 22, b"ctx", 32, b"salt")
        ev = key_derivation_audit_event("derived", record, 7)
        self.assertEqual(ev["schema"], KEY_DERIVATION_SCHEMA)
        self.assertEqual(ev["kind"], "derived")
        self.assertEqual(ev["seq"], 7)
        self.assertEqual(ev["key_pin"], record.key_pin)
        self.assertNotIn("key_bytes", ev)

    def test_bad_kind_rejected(self):
        _, record = HKDF().derive(b"\x0b" * 22, b"ctx", 32, b"salt")
        with self.assertRaises(KDFError):
            key_derivation_audit_event("rotated", record, 0)

    def test_bad_seq_rejected(self):
        _, record = HKDF().derive(b"\x0b" * 22, b"ctx", 32, b"salt")
        with self.assertRaises(KDFError):
            key_derivation_audit_event("derived", record, -1)
        with self.assertRaises(KDFError):
            key_derivation_audit_event("derived", record, True)

    def test_kinds(self):
        _, record = HKDF().derive(b"\x0b" * 22, b"ctx", 32, b"salt")
        for kind in ("extracted", "expanded", "derived"):
            ev = key_derivation_audit_event(kind, record, 0)
            self.assertEqual(ev["kind"], kind)


if __name__ == "__main__":
    unittest.main()
