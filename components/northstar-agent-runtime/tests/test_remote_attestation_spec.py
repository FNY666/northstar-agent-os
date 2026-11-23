"""Spec-API tests for remote_attestation: RemoteAttestation facade + endorse()."""

import unittest

import remote_attestation as ra
from remote_attestation import (
    Attester,
    EndorsementRecord,
    Quote,
    RemoteAttestation,
    RemoteAttestationError,
    expected_pcrs,
    remote_attestation_audit_event,
)


def make_host(label="spec-host-1"):
    host = Attester(label)
    host.measure("bootloader", b"B" * 32)
    host.measure("kernel", b"K" * 32)
    return host


def pin_of(content: bytes) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(content).hexdigest()


class TestSpecApiPresence(unittest.TestCase):
    def test_facade_exists(self):
        self.assertTrue(issubclass(RemoteAttestation, Attester))

    def test_facade_api_shape(self):
        for name in ("quote", "verify", "endorse"):
            self.assertTrue(callable(getattr(RemoteAttestation, name)))

    def test_record_exported(self):
        self.assertEqual(ra.EndorsementRecord, EndorsementRecord)
        self.assertIn("RemoteAttestation", ra.__all__)
        self.assertIn("EndorsementRecord", ra.__all__)


class TestEndorse(unittest.TestCase):
    def test_endorse_roundtrip(self):
        host = make_host()
        rec = host.endorse("end-1", "privacy-ca-1", seq=0)
        self.assertIsInstance(rec, EndorsementRecord)
        self.assertEqual(rec.endorsement_id, "end-1")
        self.assertEqual(rec.attester_label, "spec-host-1")
        self.assertEqual(rec.issuer_label, "privacy-ca-1")
        self.assertEqual(rec.endorsement_digest, "")
        self.assertEqual(len(rec.pin), 32)
        self.assertTrue(rec.verify())

    def test_endorse_with_digest_pin(self):
        host = make_host()
        digest = pin_of(b"issuer certificate bytes")
        rec = host.endorse("end-2", "privacy-ca-1", seq=1, endorsement_digest=digest)
        self.assertEqual(rec.endorsement_digest, digest)
        self.assertTrue(rec.verify())
        self.assertEqual(rec.as_dict()["endorsement_digest"], digest)

    def test_endorse_raw_bytes_digest_refused(self):
        host = make_host()
        with self.assertRaises(RemoteAttestationError):
            host.endorse("end-9", "privacy-ca-1", seq=0, endorsement_digest=b"raw")

    def test_endorse_bad_pin_format_refused(self):
        host = make_host()
        with self.assertRaises(RemoteAttestationError):
            host.endorse("end-9", "privacy-ca-1", seq=0, endorsement_digest="sha256:zz")

    def test_endorse_duplicate_refused(self):
        host = make_host()
        host.endorse("end-1", "privacy-ca-1", seq=0)
        with self.assertRaises(RemoteAttestationError):
            host.endorse("end-1", "privacy-ca-1", seq=1)

    def test_endorse_bad_inputs(self):
        host = make_host()
        with self.assertRaises(RemoteAttestationError):
            host.endorse("", "privacy-ca-1", seq=0)
        with self.assertRaises(RemoteAttestationError):
            host.endorse(123, "privacy-ca-1", seq=0)  # type: ignore[arg-type]
        with self.assertRaises(RemoteAttestationError):
            host.endorse("end-9", "", seq=0)
        with self.assertRaises(RemoteAttestationError):
            host.endorse("end-9", "privacy-ca-1", seq=-1)
        with self.assertRaises(RemoteAttestationError):
            host.endorse("end-9", "privacy-ca-1", seq=True)

    def test_endorsement_record_frozen(self):
        host = make_host()
        rec = host.endorse("end-1", "privacy-ca-1", seq=0)
        with self.assertRaises(Exception):
            rec.issuer_label = "rogue"  # type: ignore[misc]

    def test_endorsement_record_view(self):
        host = make_host()
        booked = host.endorse("end-1", "privacy-ca-1", seq=0)
        self.assertEqual(host.endorsement_record("end-1"), booked)
        with self.assertRaises(RemoteAttestationError):
            host.endorsement_record("nope")

    def test_endorsement_ids_sorted(self):
        host = make_host()
        host.endorse("end-b", "ca", seq=0)
        host.endorse("end-a", "ca", seq=1)
        self.assertEqual(host.endorsement_ids(), ("end-a", "end-b"))

    def test_pin_determinism(self):
        a = make_host()
        b = make_host()
        pa = a.endorse("end-1", "privacy-ca-1", seq=0).pin
        pb = b.endorse("end-1", "privacy-ca-1", seq=0).pin
        self.assertEqual(pa, pb)
        pc = a.endorse("end-2", "other-ca", seq=1).pin
        self.assertNotEqual(pa, pc)

    def test_tamper_breaks_verify(self):
        host = make_host()
        rec = host.endorse("end-1", "privacy-ca-1", seq=0)
        object.__setattr__(rec, "pin", b"\x00" * 32)
        self.assertFalse(rec.verify())

    def test_endorse_does_not_affect_quotes(self):
        host = make_host()
        golden = expected_pcrs(host)
        host.endorse("end-1", "privacy-ca-1", seq=0)
        q = host.quote(b"n", seq=1)
        self.assertTrue(
            RemoteAttestation.verify(q, "spec-host-1", b"n", golden)
        )


class TestFacade(unittest.TestCase):
    def test_facade_quote_verify_roundtrip(self):
        host = RemoteAttestation("facade-host")
        host.measure("bootloader", b"B" * 32)
        golden = expected_pcrs(host)
        q = host.quote(b"challenge", seq=5)
        self.assertIsInstance(q, Quote)
        self.assertTrue(
            RemoteAttestation.verify(q, "facade-host", b"challenge", golden)
        )

    def test_facade_verify_tamper_fails(self):
        host = RemoteAttestation("facade-host")
        host.measure("bootloader", b"B" * 32)
        q = host.quote(b"challenge", seq=5)
        forged = Quote(
            label=q.label, pcrs=q.pcrs, nonce=q.nonce, seq=q.seq,
            tag=b"\x00" * 32,
        )
        self.assertFalse(
            RemoteAttestation.verify(
                forged, "facade-host", b"challenge", expected_pcrs(host)
            )
        )

    def test_facade_endorse(self):
        host = RemoteAttestation("facade-host")
        rec = host.endorse("end-1", "privacy-ca-1", seq=0)
        self.assertTrue(rec.verify())
        self.assertEqual(rec.attester_label, "facade-host")


class TestEndorseAudit(unittest.TestCase):
    def test_endorsed_shape(self):
        ev = remote_attestation_audit_event("endorsed", seq=4)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["kind"], "remote-attestation.endorsed")
        self.assertEqual(ev["module"], ra.SCHEMA_PIN)
        self.assertEqual(ev["seq"], 4)

    def test_bad_kind_still_rejected(self):
        with self.assertRaises(RemoteAttestationError):
            remote_attestation_audit_event("minted", seq=0)


class TestMain(unittest.TestCase):
    def test_main(self):
        ra.main()


if __name__ == "__main__":
    unittest.main()
