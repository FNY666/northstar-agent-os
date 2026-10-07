"""Tests for remote_attestation (TPM-style attestation, simulated)."""

import unittest

import remote_attestation as ra
from remote_attestation import (
    Attester,
    Quote,
    RemoteAttestationError,
    expected_pcrs,
    remote_attestation_audit_event,
    verify,
)


def make_host(label="host-1"):
    host = Attester(label)
    host.measure("bootloader", b"B" * 32)
    host.measure("firmware", b"F" * 32)
    host.measure("kernel", b"K" * 32)
    return host


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(ra.REMOTE_ATTESTATION_VERSION, "remote-attestation.v1")

    def test_schema_pin(self):
        self.assertEqual(ra.SCHEMA_PIN, "northstar.remote-attestation.v1")

    def test_pcr_components_closed(self):
        self.assertEqual(
            set(ra.PCR_COMPONENTS),
            {"bootloader", "firmware", "kernel", "runtime", "config"},
        )


class TestMeasure(unittest.TestCase):
    def test_measure_returns_new_pcr(self):
        host = Attester("h")
        first = host.measure("kernel", b"K" * 32)
        second = host.measure("kernel", b"K" * 32)
        self.assertNotEqual(first, second)  # extend binds history

    def test_genesis_is_zeros(self):
        host = Attester("h")
        self.assertEqual(host.pcrs()[2], b"\x00" * 32)

    def test_extend_math(self):
        import hashlib

        host = Attester("h")
        new = host.measure("runtime", b"R" * 32)
        self.assertEqual(new, hashlib.sha256(b"\x00" * 32 + b"R" * 32).digest())

    def test_unknown_component_rejected(self):
        host = Attester("h")
        with self.assertRaises(RemoteAttestationError):
            host.measure("gpu-driver", b"G" * 32)

    def test_str_digest_rejected(self):
        host = Attester("h")
        with self.assertRaises(RemoteAttestationError):
            host.measure("kernel", "not-bytes")

    def test_empty_digest_rejected(self):
        host = Attester("h")
        with self.assertRaises(RemoteAttestationError):
            host.measure("kernel", b"")

    def test_empty_label_rejected(self):
        with self.assertRaises(RemoteAttestationError):
            Attester("")


class TestQuote(unittest.TestCase):
    def test_quote_shape(self):
        host = make_host()
        q = host.quote(b"nonce-1", seq=3)
        self.assertIsInstance(q, Quote)
        self.assertEqual(q.label, "host-1")
        self.assertEqual(q.nonce, b"nonce-1")
        self.assertEqual(q.seq, 3)
        self.assertEqual(len(q.tag), 32)
        self.assertEqual(q.version, ra.REMOTE_ATTESTATION_VERSION)

    def test_quote_frozen(self):
        host = make_host()
        q = host.quote(b"n", seq=0)
        with self.assertRaises(Exception):
            q.seq = 99  # type: ignore[misc]

    def test_quote_deterministic(self):
        a = make_host()
        b = make_host()
        self.assertEqual(
            a.quote(b"n", seq=1).tag, b.quote(b"n", seq=1).tag
        )

    def test_quote_binds_seq(self):
        host = make_host()
        t1 = host.quote(b"n", seq=1).tag
        t2 = host.quote(b"n", seq=2).tag
        self.assertNotEqual(t1, t2)

    def test_empty_nonce_rejected(self):
        host = make_host()
        with self.assertRaises(RemoteAttestationError):
            host.quote(b"", seq=0)

    def test_bad_seq_rejected(self):
        host = make_host()
        with self.assertRaises(RemoteAttestationError):
            host.quote(b"n", seq=-1)
        with self.assertRaises(RemoteAttestationError):
            host.quote(b"n", seq=True)

    def test_quote_count(self):
        host = make_host()
        host.quote(b"a", seq=0)
        host.quote(b"b", seq=1)
        self.assertEqual(host.quote_count(), 2)

    def test_as_dict_shape(self):
        host = make_host()
        d = host.quote(b"n", seq=0).as_dict()
        self.assertEqual(d["schema"], ra.SCHEMA_PIN)
        self.assertIn("2", d["pcrs"])
        self.assertEqual(d["nonce"], b"n".hex())


class TestVerify(unittest.TestCase):
    def test_happy_path(self):
        host = make_host()
        golden = expected_pcrs(host)
        q = host.quote(b"challenge", seq=5)
        self.assertTrue(verify(q, "host-1", b"challenge", golden))

    def test_wrong_nonce_fails(self):
        host = make_host()
        q = host.quote(b"challenge", seq=5)
        self.assertFalse(verify(q, "host-1", b"stale", expected_pcrs(host)))

    def test_tampered_pcr_fails(self):
        host = make_host()
        golden = expected_pcrs(host)
        bad = dict(golden)
        bad[0] = b"\xff" * 32
        q = host.quote(b"challenge", seq=5)
        self.assertFalse(verify(q, "host-1", b"challenge", bad))

    def test_wrong_label_fails(self):
        other = make_host("host-2")
        q = other.quote(b"challenge", seq=5)
        self.assertFalse(
            verify(q, "host-1", b"challenge", expected_pcrs(other))
        )

    def test_tampered_tag_fails(self):
        host = make_host()
        q = host.quote(b"challenge", seq=5)
        forged = Quote(
            label=q.label, pcrs=q.pcrs, nonce=q.nonce, seq=q.seq,
            tag=b"\x00" * 32,
        )
        self.assertFalse(
            verify(forged, "host-1", b"challenge", expected_pcrs(host))
        )

    def test_measurement_after_quote_fails(self):
        host = make_host()
        golden = expected_pcrs(host)
        q = host.quote(b"challenge", seq=5)
        host.measure("config", b"C" * 32)  # host changed after quoting
        self.assertFalse(verify(q, "host-1", b"challenge", expected_pcrs(host)))
        self.assertTrue(verify(q, "host-1", b"challenge", golden))

    def test_non_quote_raises(self):
        with self.assertRaises(RemoteAttestationError):
            verify("not-a-quote", "host-1", b"n", {})  # type: ignore[arg-type]

    def test_bad_expected_pcrs_raises(self):
        host = make_host()
        q = host.quote(b"n", seq=0)
        with self.assertRaises(RemoteAttestationError):
            verify(q, "host-1", b"n", {"2": b"x"})  # type: ignore[dict-item]

    def test_expected_pcrs_type_check(self):
        with self.assertRaises(RemoteAttestationError):
            expected_pcrs("nope")  # type: ignore[arg-type]


class TestAuditEvent(unittest.TestCase):
    def test_shapes(self):
        for kind in ("measured", "quoted", "verified", "rejected"):
            ev = remote_attestation_audit_event(kind, seq=9)
            self.assertEqual(ev["schema"], "audit.ndjson/1")
            self.assertEqual(ev["kind"], f"remote-attestation.{kind}")
            self.assertEqual(ev["module"], ra.SCHEMA_PIN)
            self.assertEqual(ev["seq"], 9)

    def test_bad_kind_rejected(self):
        with self.assertRaises(RemoteAttestationError):
            remote_attestation_audit_event("minted", seq=0)

    def test_bad_seq_rejected(self):
        with self.assertRaises(RemoteAttestationError):
            remote_attestation_audit_event("quoted", seq=-1)


class TestMain(unittest.TestCase):
    def test_main(self):
        ra.main()


if __name__ == "__main__":
    unittest.main()
