"""Tests for witness_enc: simulated witness encryption."""
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from witness_enc import (
    SCHEMA_PIN,
    WITNESS_ENC_VERSION,
    Ciphertext,
    Statement,
    WitnessEnc,
    WitnessEncError,
    witness_enc_audit_event,
)


def _preimage_statement(preimage: bytes = b"northstar-witness") -> tuple[Statement, bytes]:
    digest = hashlib.sha256(preimage).digest()
    return Statement("hash-preimage.v1", digest), preimage


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(WITNESS_ENC_VERSION, "witness-enc.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.witness-enc.v1")


class TestStatement(unittest.TestCase):
    def test_construction(self):
        stmt, _ = _preimage_statement()
        self.assertEqual(stmt.relation_id, "hash-preimage.v1")
        self.assertEqual(len(stmt.instance), 32)
        self.assertTrue(stmt.statement_pin.startswith("sha256:"))
        self.assertEqual(len(stmt.statement_pin), len("sha256:") + 64)

    def test_pin_deterministic(self):
        a, _ = _preimage_statement()
        b, _ = _preimage_statement()
        self.assertEqual(a.statement_pin, b.statement_pin)

    def test_pin_binds_instance(self):
        a, _ = _preimage_statement(b"one")
        b, _ = _preimage_statement(b"two")
        self.assertNotEqual(a.statement_pin, b.statement_pin)

    def test_pin_binds_relation(self):
        digest = hashlib.sha256(b"x").digest()
        a = Statement("hash-preimage.v1", digest)
        b = Statement("prefix.v1", b"auth:")
        self.assertNotEqual(a.statement_pin, b.statement_pin)

    def test_bad_relation_rejected(self):
        with self.assertRaises(WitnessEncError):
            Statement("no-such-relation.v9", b"instance")

    def test_non_str_relation_rejected(self):
        with self.assertRaises(WitnessEncError):
            Statement(123, b"instance")

    def test_preimage_instance_must_be_32_bytes(self):
        with self.assertRaises(WitnessEncError):
            Statement("hash-preimage.v1", b"too-short")

    def test_instance_must_be_bytes(self):
        with self.assertRaises(WitnessEncError):
            Statement("prefix.v1", "not-bytes")

    def test_prefix_statement_allows_any_bytes(self):
        stmt = Statement("prefix.v1", b"")
        self.assertEqual(stmt.instance, b"")

    def test_frozen(self):
        stmt, _ = _preimage_statement()
        with self.assertRaises(FrozenInstanceError):
            stmt.relation_id = "prefix.v1"  # type: ignore[misc]

    def test_as_dict(self):
        stmt, _ = _preimage_statement()
        d = stmt.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["relation_id"], "hash-preimage.v1")
        self.assertEqual(d["instance"], hashlib.sha256(b"northstar-witness").digest().hex())
        self.assertEqual(d["statement_pin"], stmt.statement_pin)


class TestEncryptDecrypt(unittest.TestCase):
    def setUp(self):
        self.we = WitnessEnc()
        self.stmt, self.preimage = _preimage_statement()

    def test_roundtrip(self):
        ct = self.we.encrypt(b"secret payload", self.stmt)
        self.assertEqual(self.we.decrypt(ct, self.preimage), b"secret payload")

    def test_wrong_witness_returns_none(self):
        ct = self.we.encrypt(b"secret payload", self.stmt)
        self.assertIsNone(self.we.decrypt(ct, b"wrong"))

    def test_witness_for_other_statement_returns_none(self):
        ct = self.we.encrypt(b"secret payload", self.stmt)
        self.assertIsNone(self.we.decrypt(ct, b"other"))

    def test_deterministic(self):
        a = self.we.encrypt(b"data", self.stmt)
        b = self.we.encrypt(b"data", self.stmt)
        self.assertEqual(a.ciphertext, b.ciphertext)
        self.assertEqual(a.tag, b.tag)

    def test_different_data_different_ciphertext(self):
        a = self.we.encrypt(b"data-a", self.stmt)
        b = self.we.encrypt(b"data-b", self.stmt)
        self.assertNotEqual(a.ciphertext, b.ciphertext)

    def test_different_statement_different_ciphertext(self):
        other, _ = _preimage_statement(b"different")
        a = self.we.encrypt(b"data", self.stmt)
        b = self.we.encrypt(b"data", other)
        self.assertNotEqual(a.ciphertext, b.ciphertext)

    def test_empty_data_roundtrip(self):
        ct = self.we.encrypt(b"", self.stmt)
        self.assertEqual(self.we.decrypt(ct, self.preimage), b"")

    def test_large_data_roundtrip(self):
        data = bytes(range(256)) * 40  # 10240 bytes, multi-block keystream
        ct = self.we.encrypt(data, self.stmt)
        self.assertEqual(self.we.decrypt(ct, self.preimage), data)

    def test_tampered_ciphertext_returns_none(self):
        ct = self.we.encrypt(b"secret", self.stmt)
        tampered = Ciphertext(
            statement=ct.statement,
            ciphertext=bytes([ct.ciphertext[0] ^ 0xFF]) + ct.ciphertext[1:],
            tag=ct.tag,
        )
        self.assertIsNone(self.we.decrypt(tampered, self.preimage))

    def test_tampered_tag_returns_none(self):
        ct = self.we.encrypt(b"secret", self.stmt)
        tampered = Ciphertext(
            statement=ct.statement,
            ciphertext=ct.ciphertext,
            tag=bytes([ct.tag[0] ^ 0xFF]) + ct.tag[1:],
        )
        self.assertIsNone(self.we.decrypt(tampered, self.preimage))

    def test_statement_swap_returns_none(self):
        ct = self.we.encrypt(b"secret", self.stmt)
        other, other_preimage = _preimage_statement(b"other")
        swapped = Ciphertext(statement=other, ciphertext=ct.ciphertext, tag=ct.tag)
        # The witness is valid for `other`, but the tag was keyed to `stmt`.
        self.assertIsNone(self.we.decrypt(swapped, other_preimage))

    def test_encrypt_rejects_str_data(self):
        with self.assertRaises(WitnessEncError):
            self.we.encrypt("not-bytes", self.stmt)

    def test_encrypt_rejects_non_statement(self):
        with self.assertRaises(WitnessEncError):
            self.we.encrypt(b"data", "not-a-statement")

    def test_decrypt_rejects_non_ciphertext(self):
        with self.assertRaises(WitnessEncError):
            self.we.decrypt("not-a-ciphertext", self.preimage)

    def test_decrypt_rejects_non_bytes_witness(self):
        ct = self.we.encrypt(b"data", self.stmt)
        with self.assertRaises(WitnessEncError):
            self.we.decrypt(ct, "not-bytes")

    def test_ciphertext_frozen(self):
        ct = self.we.encrypt(b"data", self.stmt)
        with self.assertRaises(FrozenInstanceError):
            ct.tag = b"0" * 16  # type: ignore[misc]

    def test_ciphertext_bad_tag_length(self):
        ct = self.we.encrypt(b"data", self.stmt)
        with self.assertRaises(WitnessEncError):
            Ciphertext(statement=ct.statement, ciphertext=ct.ciphertext, tag=b"short")

    def test_ciphertext_as_dict(self):
        ct = self.we.encrypt(b"data", self.stmt)
        d = ct.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["statement"]["statement_pin"], self.stmt.statement_pin)
        self.assertEqual(d["ciphertext"], ct.ciphertext.hex())
        self.assertEqual(d["tag"], ct.tag.hex())


class TestPrefixRelation(unittest.TestCase):
    def setUp(self):
        self.we = WitnessEnc()
        self.stmt = Statement("prefix.v1", b"auth:")

    def test_prefixed_witness_decrypts(self):
        ct = self.we.encrypt(b"token-data", self.stmt)
        self.assertEqual(self.we.decrypt(ct, b"auth:token-123"), b"token-data")

    def test_unprefixed_witness_returns_none(self):
        ct = self.we.encrypt(b"token-data", self.stmt)
        self.assertIsNone(self.we.decrypt(ct, b"nope"))

    def test_exact_prefix_witness_decrypts(self):
        ct = self.we.encrypt(b"token-data", self.stmt)
        self.assertEqual(self.we.decrypt(ct, b"auth:"), b"token-data")


class TestAuditEvents(unittest.TestCase):
    def test_shapes(self):
        for kind in ("encrypted", "decrypted", "decrypt-refused"):
            ev = witness_enc_audit_event(kind, {"statement_pin": "sha256:" + "0" * 64}, 7)
            self.assertEqual(ev["schema"], SCHEMA_PIN)
            self.assertEqual(ev["kind"], f"witness-enc.{kind}")
            self.assertEqual(ev["audit_seq"], 7)

    def test_bad_kind_rejected(self):
        with self.assertRaises(WitnessEncError):
            witness_enc_audit_event("nope", {}, 0)

    def test_bad_seq_rejected(self):
        with self.assertRaises(WitnessEncError):
            witness_enc_audit_event("encrypted", {}, -1)
        with self.assertRaises(WitnessEncError):
            witness_enc_audit_event("encrypted", {}, True)

    def test_non_mapping_record_rejected(self):
        with self.assertRaises(WitnessEncError):
            witness_enc_audit_event("encrypted", "not-a-mapping", 0)


class TestMain(unittest.TestCase):
    def test_main(self):
        import witness_enc as mod

        mod.main()  # asserts internally; raises on failure


if __name__ == "__main__":
    unittest.main()
