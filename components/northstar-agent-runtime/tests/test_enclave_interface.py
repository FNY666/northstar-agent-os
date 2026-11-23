"""Tests for enclave_interface (secure enclave: attest/execute/seal, simulated)."""

import hashlib
import unittest

from enclave_interface import (
    VERSION,
    SCHEMA,
    TEE_TYPES,
    AttestationError,
    AttestationQuote,
    Enclave,
    EnclaveConfig,
    ExecutionError,
    SealedData,
    SealingError,
    enclave_audit_event,
    register_op,
    registered_ops,
    verify_quote,
)


def _measurement(tag: bytes = b"test-enclave-code") -> str:
    return "sha256:" + hashlib.sha256(tag).hexdigest()


def _config(**kw) -> EnclaveConfig:
    base = {
        "enclave_id": "enc-test",
        "tee_type": "software",
        "measurement": _measurement(),
    }
    base.update(kw)
    return EnclaveConfig(**base)


class PinsTest(unittest.TestCase):
    def test_version(self):
        self.assertEqual(VERSION, "enclave-interface.v1")

    def test_schema(self):
        self.assertEqual(SCHEMA, "northstar.enclave-interface.v1")

    def test_tee_types(self):
        self.assertIn("software", TEE_TYPES)
        self.assertIn("sgx", TEE_TYPES)
        self.assertIn("sev-snp", TEE_TYPES)
        self.assertIn("tdx", TEE_TYPES)


class ConfigTest(unittest.TestCase):
    def test_empty_id(self):
        with self.assertRaises(ValueError):
            _config(enclave_id="")

    def test_bad_tee_type(self):
        with self.assertRaises(ValueError):
            _config(tee_type="trustzone")

    def test_bad_measurement(self):
        with self.assertRaises(ValueError):
            _config(measurement="not-a-pin")

    def test_bool_max_data(self):
        with self.assertRaises(TypeError):
            _config(max_data_bytes=True)

    def test_zero_max_data(self):
        with self.assertRaises(ValueError):
            _config(max_data_bytes=0)


class AttestTest(unittest.TestCase):
    def test_attest_shape(self):
        enc = Enclave(_config())
        q = enc.attest(b"n1", 1)
        self.assertEqual(q.enclave_id, "enc-test")
        self.assertTrue(q.emulated)
        self.assertEqual(q.tee_type, "software")
        self.assertEqual(q.nonce, b"n1".hex())
        self.assertEqual(q.seq, 1)

    def test_attest_empty_nonce(self):
        enc = Enclave(_config())
        with self.assertRaises(AttestationError):
            enc.attest(b"", 1)

    def test_attest_seq_strict(self):
        enc = Enclave(_config())
        enc.attest(b"a", 1)
        with self.assertRaises(AttestationError):
            enc.attest(b"b", 1)
        with self.assertRaises(AttestationError):
            enc.attest(b"b", 0)

    def test_attest_bool_seq(self):
        enc = Enclave(_config())
        with self.assertRaises(TypeError):
            enc.attest(b"a", True)

    def test_quote_liveness(self):
        enc = Enclave(_config())
        q = enc.quote(5)
        self.assertEqual(q.nonce, "")
        self.assertEqual(q.seq, 5)


class VerifyTest(unittest.TestCase):
    def test_verify_happy(self):
        cfg = _config()
        enc = Enclave(cfg)
        q = enc.attest(b"fresh", 3)
        self.assertTrue(
            verify_quote(q, expected_measurement=cfg.measurement,
                         expected_nonce=b"fresh", min_seq=3)
        )

    def test_verify_wrong_measurement(self):
        enc = Enclave(_config())
        q = enc.attest(b"n", 1)
        self.assertFalse(
            verify_quote(q, expected_measurement=_measurement(b"other"))
        )

    def test_verify_wrong_nonce(self):
        cfg = _config()
        enc = Enclave(cfg)
        q = enc.attest(b"n", 1)
        self.assertFalse(
            verify_quote(q, expected_measurement=cfg.measurement,
                         expected_nonce=b"wrong")
        )

    def test_verify_min_seq(self):
        cfg = _config()
        enc = Enclave(cfg)
        q = enc.attest(b"n", 1)
        self.assertFalse(
            verify_quote(q, expected_measurement=cfg.measurement, min_seq=2)
        )

    def test_verify_tampered_mac(self):
        cfg = _config()
        enc = Enclave(cfg)
        q = enc.attest(b"n", 1)
        bad = AttestationQuote(
            enclave_id=q.enclave_id, tee_type=q.tee_type,
            measurement=q.measurement, nonce=q.nonce, seq=q.seq,
            emulated=q.emulated, mac="0" * 64,
        )
        self.assertFalse(verify_quote(bad, expected_measurement=cfg.measurement))

    def test_emulated_claiming_hardware_rejected(self):
        cfg = _config()
        enc = Enclave(cfg)
        q = enc.attest(b"n", 1)
        forged = AttestationQuote(
            enclave_id=q.enclave_id, tee_type="sgx",
            measurement=q.measurement, nonce=q.nonce, seq=q.seq,
            emulated=True, mac=q.mac,
        )
        self.assertFalse(verify_quote(forged, expected_measurement=cfg.measurement))

    def test_allow_emulated_false(self):
        cfg = _config()
        enc = Enclave(cfg)
        q = enc.attest(b"n", 1)
        self.assertFalse(
            verify_quote(q, expected_measurement=cfg.measurement,
                         allow_emulated=False)
        )


class ExecuteTest(unittest.TestCase):
    def test_execute_sha256(self):
        enc = Enclave(_config())
        r = enc.execute("sha256", b"hello", 1)
        self.assertEqual(r.op_name, "sha256")
        self.assertEqual(r.seq, 1)
        self.assertTrue(
            verify_quote(r.quote, expected_measurement=_measurement())
        )

    def test_execute_unknown_op(self):
        enc = Enclave(_config())
        with self.assertRaises(ExecutionError):
            enc.execute("eval", b"x", 1)

    def test_execute_non_bytes(self):
        enc = Enclave(_config())
        with self.assertRaises(ExecutionError):
            enc.execute("identity", "str-not-bytes", 1)

    def test_execute_too_large(self):
        cfg = _config(max_data_bytes=4)
        enc = Enclave(cfg)
        with self.assertRaises(ExecutionError):
            enc.execute("identity", b"12345", 1)

    def test_register_custom_op(self):
        register_op("upper", lambda b: b.upper())
        self.assertIn("upper", registered_ops())
        enc = Enclave(_config())
        r = enc.execute("upper", b"abc", 1)
        self.assertEqual(r.op_name, "upper")


class SealTest(unittest.TestCase):
    def test_roundtrip(self):
        enc = Enclave(_config())
        sealed = enc.seal(b"top secret", 7)
        self.assertIsInstance(sealed, SealedData)
        self.assertEqual(enc.unseal(sealed), b"top secret")

    def test_unseal_wrong_measurement(self):
        enc = Enclave(_config())
        sealed = enc.seal(b"x", 1)
        other = Enclave(_config(measurement=_measurement(b"other-code")))
        with self.assertRaises(SealingError):
            other.unseal(sealed)

    def test_unseal_tampered_tag(self):
        enc = Enclave(_config())
        sealed = enc.seal(b"x", 1)
        bad = SealedData(
            enclave_id=sealed.enclave_id, measurement=sealed.measurement,
            seq=sealed.seq, ciphertext=sealed.ciphertext, tag="0" * 64,
        )
        with self.assertRaises(SealingError):
            enc.unseal(bad)

    def test_unseal_wrong_enclave(self):
        enc = Enclave(_config())
        sealed = enc.seal(b"x", 1)
        other = Enclave(_config(enclave_id="enc-other"))
        with self.assertRaises(SealingError):
            other.unseal(sealed)

    def test_seal_non_bytes(self):
        enc = Enclave(_config())
        with self.assertRaises(SealingError):
            enc.seal("nope", 1)


class AuditTest(unittest.TestCase):
    def test_event_shape(self):
        ev = enclave_audit_event("enclave-executed", 9, enclave_id="enc-1",
                                 detail={"op": "sha256"})
        self.assertEqual(ev["schema_version"], "northstar.audit.v1")
        self.assertEqual(ev["event_type"], "enclave.enclave-executed")
        self.assertEqual(ev["seq"], 9)
        self.assertEqual(ev["enclave_id"], "enc-1")

    def test_bad_kind(self):
        with self.assertRaises(ValueError):
            enclave_audit_event("nope", 1)

    def test_bad_seq(self):
        with self.assertRaises(TypeError):
            enclave_audit_event("sealed", True)


class MainTest(unittest.TestCase):
    def test_main(self):
        import enclave_interface
        enclave_interface.main()


if __name__ == "__main__":
    unittest.main()
