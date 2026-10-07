"""Tests for ring_sig: anonymous signing over an ad-hoc anonymity set."""

import unittest

from ring_sig import (
    RING_SIG_SCHEMA,
    RING_SIG_VERSION,
    EVENT_LINKED,
    EVENT_REJECTED,
    EVENT_SIGNED,
    EVENT_UNLINKED,
    EVENT_VERIFIED,
    BadRingError,
    Keypair,
    RingSig,
    RingSigError,
    RingSignature,
    VerificationError,
    generate_keypair,
    ring_signature_audit_event,
)


def make_ring(n):
    return [generate_keypair(f"member-{i}") for i in range(n)]


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(RING_SIG_VERSION, "ring-sig.v1")

    def test_schema_pin(self):
        self.assertEqual(RING_SIG_SCHEMA, "northstar.ring-sig.v1")


class TestKeypair(unittest.TestCase):
    def test_deterministic(self):
        self.assertEqual(generate_keypair("a"), generate_keypair("a"))

    def test_distinct_labels(self):
        self.assertNotEqual(generate_keypair("a"), generate_keypair("b"))

    def test_secret_never_in_as_dict(self):
        kp = generate_keypair("a")
        d = kp.as_dict()
        self.assertNotIn(kp.secret, str(d))
        self.assertIn("secret_digest", d)

    def test_bad_label(self):
        with self.assertRaises(TypeError):
            generate_keypair("")
        with self.assertRaises(TypeError):
            generate_keypair(None)


class TestSign(unittest.TestCase):
    def test_sign_verify_happy(self):
        ring = make_ring(4)
        sig = RingSig.sign("hello", ring, 2)
        self.assertTrue(RingSig.verify("hello", ring, sig))

    def test_every_member_can_sign(self):
        ring = make_ring(5)
        for i in range(5):
            sig = RingSig.sign("m", ring, i)
            self.assertTrue(RingSig.verify("m", ring, sig))

    def test_deterministic(self):
        ring = make_ring(3)
        s1 = RingSig.sign("m", ring, 1)
        s2 = RingSig.sign("m", ring, 1)
        self.assertEqual(s1.as_dict(), s2.as_dict())

    def test_bytes_message(self):
        ring = make_ring(3)
        sig = RingSig.sign(b"bytes-msg", ring, 0)
        self.assertTrue(RingSig.verify(b"bytes-msg", ring, sig))

    def test_wrong_message_fails(self):
        ring = make_ring(3)
        sig = RingSig.sign("a", ring, 0)
        self.assertFalse(RingSig.verify("b", ring, sig))

    def test_wrong_ring_fails(self):
        ring = make_ring(3)
        other = [generate_keypair(f"other-{i}") for i in range(3)]
        sig = RingSig.sign("m", ring, 0)
        self.assertFalse(RingSig.verify("m", other, sig))

    def test_reordered_ring_fails(self):
        ring = make_ring(3)
        sig = RingSig.sign("m", ring, 0)
        self.assertFalse(RingSig.verify("m", list(reversed(ring)), sig))

    def test_tampered_response_fails(self):
        ring = make_ring(3)
        sig = RingSig.sign("m", ring, 1)
        bad_responses = (sig.responses[0], "sha256:" + "ff" * 32, sig.responses[2])
        bad = RingSignature(
            message_digest=sig.message_digest,
            ring_digest=sig.ring_digest,
            ring_size=sig.ring_size,
            responses=bad_responses,
            challenge=sig.challenge,
            key_image=None,
            linkable=False,
        )
        self.assertFalse(RingSig.verify("m", ring, bad))

    def test_tampered_challenge_fails(self):
        ring = make_ring(3)
        sig = RingSig.sign("m", ring, 0)
        bad = RingSignature(
            message_digest=sig.message_digest,
            ring_digest=sig.ring_digest,
            ring_size=sig.ring_size,
            responses=sig.responses,
            challenge="sha256:" + "00" * 32,
            key_image=None,
            linkable=False,
        )
        self.assertFalse(RingSig.verify("m", ring, bad))

    def test_signer_index_hidden(self):
        ring = make_ring(4)
        sig = RingSig.sign("m", ring, 3)
        d = sig.as_dict()
        self.assertNotIn("signer", str(d).lower().replace("signer-response", ""))


class TestRingValidation(unittest.TestCase):
    def test_empty_ring(self):
        with self.assertRaises(BadRingError):
            RingSig.sign("m", [], 0)

    def test_duplicate_members(self):
        kp = generate_keypair("dup")
        with self.assertRaises(BadRingError):
            RingSig.sign("m", [kp, kp], 0)

    def test_bad_signer_idx(self):
        ring = make_ring(3)
        with self.assertRaises(BadRingError):
            RingSig.sign("m", ring, 3)
        with self.assertRaises(BadRingError):
            RingSig.sign("m", ring, -1)
        with self.assertRaises(TypeError):
            RingSig.sign("m", ring, True)

    def test_non_keypair_member(self):
        with self.assertRaises(BadRingError):
            RingSig.sign("m", ["not-a-keypair"], 0)

    def test_bad_message_type(self):
        ring = make_ring(2)
        with self.assertRaises(TypeError):
            RingSig.sign(123, ring, 0)

    def test_bad_linkable_type(self):
        ring = make_ring(2)
        with self.assertRaises(TypeError):
            RingSig.sign("m", ring, 0, linkable="yes")


class TestLinkability(unittest.TestCase):
    def test_same_signer_links(self):
        ring = make_ring(4)
        a = RingSig.sign("m1", ring, 1, linkable=True)
        b = RingSig.sign("m2", ring, 1, linkable=True)
        self.assertTrue(RingSig.link(a, b))

    def test_different_signers_do_not_link(self):
        ring = make_ring(4)
        a = RingSig.sign("m", ring, 1, linkable=True)
        b = RingSig.sign("m", ring, 2, linkable=True)
        self.assertFalse(RingSig.link(a, b))

    def test_nonlinkable_never_links(self):
        ring = make_ring(4)
        a = RingSig.sign("m1", ring, 1)
        b = RingSig.sign("m2", ring, 1)
        self.assertFalse(RingSig.link(a, b))
        self.assertFalse(RingSig.link(a, RingSig.sign("m3", ring, 1, linkable=True)))

    def test_key_image_stable_across_rings(self):
        ring_a = make_ring(3)
        ring_b = [generate_keypair(f"other-{i}") for i in range(5)]
        a = RingSig.sign("m", ring_a, 0, linkable=True)
        b = RingSig.sign("m", ring_b, 0, linkable=True)
        # different signers (different labels) -> different images
        self.assertFalse(RingSig.link(a, b))

    def test_link_bad_types_raise(self):
        ring = make_ring(2)
        sig = RingSig.sign("m", ring, 0, linkable=True)
        with self.assertRaises(VerificationError):
            RingSig.link(sig, "nope")


class TestSignatureRecord(unittest.TestCase):
    def test_frozen(self):
        ring = make_ring(2)
        sig = RingSig.sign("m", ring, 0)
        with self.assertRaises(Exception):
            sig.challenge = "x"

    def test_as_dict_shape(self):
        ring = make_ring(2)
        sig = RingSig.sign("m", ring, 0)
        d = sig.as_dict()
        self.assertEqual(d["schema"], RING_SIG_SCHEMA)
        self.assertEqual(d["module"], RING_SIG_VERSION)
        self.assertEqual(d["ring_size"], 2)
        self.assertIsNone(d["key_image"])
        self.assertFalse(d["linkable"])

    def test_linkable_as_dict_shape(self):
        ring = make_ring(2)
        sig = RingSig.sign("m", ring, 0, linkable=True)
        d = sig.as_dict()
        self.assertTrue(d["linkable"])
        self.assertTrue(d["key_image"].startswith("sha256:"))

    def test_record_validation(self):
        with self.assertRaises(TypeError):
            RingSignature("bad", "sha256:x", 1, ("sha256:x",), "sha256:x", None, False)
        with self.assertRaises(TypeError):
            RingSignature(
                "sha256:x",
                "sha256:x",
                1,
                ("sha256:x",),
                "sha256:x",
                "sha256:x",
                False,
            )  # key_image on non-linkable
        with self.assertRaises(ValueError):
            RingSignature(
                "sha256:x", "sha256:x", 2, ("sha256:x",), "sha256:x", None, False
            )  # length mismatch


class TestAuditEvent(unittest.TestCase):
    def test_signed_shape(self):
        ring = make_ring(2)
        sig = RingSig.sign("m", ring, 0)
        ev = ring_signature_audit_event(EVENT_SIGNED, sig, 7)
        self.assertEqual(ev["schema"], "northstar.audit.ndjson/1")
        self.assertEqual(ev["event"], EVENT_SIGNED)
        self.assertEqual(ev["module"], RING_SIG_VERSION)
        self.assertEqual(ev["audit_seq"], 7)

    def test_all_kinds(self):
        ring = make_ring(2)
        sig = RingSig.sign("m", ring, 0)
        kp = generate_keypair("x")
        for kind, rec in [
            (EVENT_SIGNED, sig),
            (EVENT_VERIFIED, sig),
            (EVENT_REJECTED, sig),
            (EVENT_LINKED, sig),
            (EVENT_UNLINKED, kp),
        ]:
            ev = ring_signature_audit_event(kind, rec, 1)
            self.assertEqual(ev["event"], kind)

    def test_bad_kind(self):
        ring = make_ring(2)
        sig = RingSig.sign("m", ring, 0)
        with self.assertRaises(ValueError):
            ring_signature_audit_event("nope", sig, 1)

    def test_bad_record(self):
        with self.assertRaises(TypeError):
            ring_signature_audit_event(EVENT_SIGNED, "nope", 1)

    def test_bad_seq(self):
        ring = make_ring(2)
        sig = RingSig.sign("m", ring, 0)
        with self.assertRaises(TypeError):
            ring_signature_audit_event(EVENT_SIGNED, sig, True)


class TestVerifyInput(unittest.TestCase):
    def test_bad_signature_type_raises(self):
        ring = make_ring(2)
        with self.assertRaises(VerificationError):
            RingSig.verify("m", ring, "nope")


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        import ring_sig as mod

        mod.main()


if __name__ == "__main__":
    unittest.main()
