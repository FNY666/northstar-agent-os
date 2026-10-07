"""Tests for fe_interface.py (functional encryption, simulated)."""

import unittest

from fe_interface import (
    Ciphertext,
    CiphertextIntegrityError,
    FE,
    FEError,
    FE_SCHEMA,
    FE_VERSION,
    FunctionKey,
    FUNCTIONS,
    fe_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(FE_VERSION, "fe-interface.v1")
        self.assertEqual(FE_SCHEMA, "northstar.fe-interface.v1")

    def test_vocabulary_pinned(self):
        self.assertEqual(sorted(FUNCTIONS), ["count", "max", "mean", "min", "sum"])


class TestSetup(unittest.TestCase):
    def test_setup_deterministic_same_label(self):
        a = FE.setup("lab-a")
        b = FE.setup("lab-a")
        self.assertEqual(a.authority_id, b.authority_id)
        self.assertEqual(a.master_public_pin, b.master_public_pin)

    def test_setup_label_isolation(self):
        a = FE.setup("lab-a")
        b = FE.setup("lab-b")
        self.assertNotEqual(a.authority_id, b.authority_id)

    def test_setup_rejects_bad_label(self):
        for bad in ("", 123, None, b"x", True):
            with self.assertRaises(FEError):
                FE.setup(bad)


class TestKeygen(unittest.TestCase):
    def setUp(self):
        self.fe = FE.setup("keygen-lab")

    def test_keygen_unknown_function_rejected(self):
        for bad in ("median", "", "SUM", 42, None):
            with self.assertRaises(FEError):
                self.fe.keygen(bad)

    def test_keygen_binds_authority_and_function(self):
        key = self.fe.keygen("sum")
        self.assertEqual(key.authority_id, self.fe.authority_id)
        self.assertEqual(key.function_id, "sum")
        self.assertTrue(key.key_id.startswith("sha256:"))
        self.assertTrue(key.function_digest.startswith("sha256:"))

    def test_keygen_deterministic(self):
        self.assertEqual(self.fe.keygen("sum"), self.fe.keygen("sum"))

    def test_function_key_frozen(self):
        key = self.fe.keygen("sum")
        with self.assertRaises(Exception):
            key.function_id = "mean"


class TestEncryptDecrypt(unittest.TestCase):
    def setUp(self):
        self.fe = FE.setup("enc-lab")
        self.data = [1.0, 2.0, 3.0, 4.0]

    def test_correctness_all_functions(self):
        ct = self.fe.encrypt(self.data)
        self.assertEqual(self.fe.decrypt(self.fe.keygen("sum"), ct), 10.0)
        self.assertEqual(self.fe.decrypt(self.fe.keygen("mean"), ct), 2.5)
        self.assertEqual(self.fe.decrypt(self.fe.keygen("max"), ct), 4.0)
        self.assertEqual(self.fe.decrypt(self.fe.keygen("min"), ct), 1.0)
        self.assertEqual(self.fe.decrypt(self.fe.keygen("count"), ct), 4)

    def test_function_restriction_never_raw_data(self):
        ct = self.fe.encrypt(self.data)
        # A "count" key returns a count; the raw list is never exposed.
        out = self.fe.decrypt(self.fe.keygen("count"), ct)
        self.assertEqual(out, 4)
        self.assertNotEqual(out, self.data)

    def test_empty_list_edges(self):
        ct = self.fe.encrypt([])
        self.assertEqual(self.fe.decrypt(self.fe.keygen("sum"), ct), 0.0)
        self.assertEqual(self.fe.decrypt(self.fe.keygen("count"), ct), 0)
        for fn in ("mean", "max", "min"):
            with self.assertRaises(FEError):
                self.fe.decrypt(self.fe.keygen(fn), ct)

    def test_big_ints_exact(self):
        big = [2 ** 60, 2 ** 61]
        ct = self.fe.encrypt(big)
        self.assertEqual(self.fe.decrypt(self.fe.keygen("sum"), ct), float(2 ** 60 + 2 ** 61))
        self.assertEqual(self.fe.decrypt(self.fe.keygen("max"), ct), float(2 ** 61))

    def test_rejects_bad_data(self):
        for bad in ([1, True], [float("nan")], [float("inf")], ["a"], "nope", 42, None, [[1]]):
            with self.assertRaises(FEError):
                self.fe.encrypt(bad)

    def test_ciphertext_tamper_fails_closed(self):
        ct = self.fe.encrypt(self.data)
        tampered = Ciphertext(
            authority_id=ct.authority_id,
            nonce=ct.nonce,
            sealed=bytes(b ^ 0xFF for b in ct.sealed),
            data_pin=ct.data_pin,
            mac=ct.mac,
        )
        with self.assertRaises(CiphertextIntegrityError):
            self.fe.decrypt(self.fe.keygen("sum"), tampered)

    def test_mac_tamper_fails_closed(self):
        ct = self.fe.encrypt(self.data)
        tampered = Ciphertext(
            authority_id=ct.authority_id,
            nonce=ct.nonce,
            sealed=ct.sealed,
            data_pin=ct.data_pin,
            mac="sha256:" + "00" * 32,
        )
        with self.assertRaises(CiphertextIntegrityError):
            self.fe.decrypt(self.fe.keygen("sum"), tampered)

    def test_cross_authority_isolation(self):
        other = FE.setup("other-lab")
        ct = self.fe.encrypt(self.data)
        with self.assertRaises(FEError):
            other.decrypt(other.keygen("sum"), ct)
        with self.assertRaises(FEError):
            self.fe.decrypt(other.keygen("sum"), ct)

    def test_decrypt_type_validation(self):
        ct = self.fe.encrypt(self.data)
        with self.assertRaises(FEError):
            self.fe.decrypt("not-a-key", ct)
        with self.assertRaises(FEError):
            self.fe.decrypt(self.fe.keygen("sum"), "not-a-ct")

    def test_ciphertext_frozen(self):
        ct = self.fe.encrypt(self.data)
        with self.assertRaises(Exception):
            ct.mac = "x"

    def test_encrypt_nonce_varies_decrypt_agrees(self):
        ct1 = self.fe.encrypt(self.data)
        ct2 = self.fe.encrypt(self.data)
        self.assertNotEqual(ct1.nonce, ct2.nonce)
        key = self.fe.keygen("sum")
        self.assertEqual(self.fe.decrypt(key, ct1), self.fe.decrypt(key, ct2))

    def test_int_inputs_accepted(self):
        ct = self.fe.encrypt([1, 2, 3])
        self.assertEqual(self.fe.decrypt(self.fe.keygen("sum"), ct), 6.0)


class TestAudit(unittest.TestCase):
    def test_audit_event_shapes(self):
        for kind in ("setup", "key-issued", "encrypted", "decrypted", "decrypt-rejected"):
            ev = fe_audit_event(kind, 7)
            self.assertEqual(ev["schema"], "audit.ndjson/1")
            self.assertEqual(ev["kind"], f"fe-interface.{kind}")
            self.assertEqual(ev["module"], FE_SCHEMA)
            self.assertEqual(ev["seq"], 7)

    def test_audit_event_rejects(self):
        with self.assertRaises(ValueError):
            fe_audit_event("nope", 0)
        for bad_seq in (-1, True, "0", None):
            with self.assertRaises(ValueError):
                fe_audit_event("setup", bad_seq)


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        import fe_interface

        fe_interface.main()


if __name__ == "__main__":
    unittest.main()
