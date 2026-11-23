"""Tests for vrf_interface: simulated VRF prove/verify shape and bindings."""
import unittest

from vrf_interface import (
    VERSION,
    SCHEMA,
    VRF,
    VRFError,
    VRFProof,
    KeyPair,
    generate_keypair,
    verify,
    vrf_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(VERSION, "vrf-interface.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA, "northstar.vrf-interface.v1")


class TestKeyGeneration(unittest.TestCase):
    def test_deterministic(self):
        a = generate_keypair(b"seed")
        b = generate_keypair(b"seed")
        self.assertEqual(a, b)

    def test_distinct_seeds(self):
        a = generate_keypair(b"seed-a")
        b = generate_keypair(b"seed-b")
        self.assertNotEqual(a.public_key, b.public_key)
        self.assertNotEqual(a.secret_key, b.secret_key)

    def test_keypair_consistency(self):
        kp = generate_keypair(b"seed")
        vrf = VRF(kp.secret_key)
        self.assertEqual(vrf.public_key, kp.public_key)

    def test_keypair_rejects_mismatched(self):
        kp = generate_keypair(b"seed")
        other = generate_keypair(b"other")
        with self.assertRaises(VRFError):
            KeyPair(secret_key=kp.secret_key, public_key=other.public_key)

    def test_reject_bad_seed(self):
        for bad in (b"", "", None, 123, True):
            with self.assertRaises(VRFError, msg=repr(bad)):
                generate_keypair(bad)

    def test_vrf_rejects_bad_secret(self):
        for bad in ("", "zzz", "0" * 63, "g" * 64, 123, None, True):
            with self.assertRaises(VRFError, msg=repr(bad)):
                VRF(bad)


class TestProve(unittest.TestCase):
    def setUp(self):
        self.vrf = VRF(generate_keypair(b"prove-seed").secret_key)

    def test_deterministic(self):
        out1, proof1 = self.vrf.prove("alpha")
        out2, proof2 = self.vrf.prove("alpha")
        self.assertEqual(out1, out2)
        self.assertEqual(proof1, proof2)

    def test_distinct_inputs_distinct_outputs(self):
        out1, _ = self.vrf.prove("alpha-1")
        out2, _ = self.vrf.prove("alpha-2")
        self.assertNotEqual(out1, out2)

    def test_bytes_input(self):
        out, proof = self.vrf.prove(b"alpha-bytes")
        self.assertTrue(verify(self.vrf.public_key, b"alpha-bytes", out, proof))

    def test_proof_shape(self):
        out, proof = self.vrf.prove("alpha")
        self.assertIsInstance(proof, VRFProof)
        self.assertEqual(proof.public_key, self.vrf.public_key)
        self.assertEqual(proof.output_digest, out)
        d = proof.as_dict()
        self.assertEqual(d["version"], VERSION)
        self.assertEqual(d["schema"], SCHEMA)

    def test_reject_bad_alpha(self):
        for bad in ("", b"", None, 123, True, ["x"]):
            with self.assertRaises(VRFError, msg=repr(bad)):
                self.vrf.prove(bad)


class TestVerify(unittest.TestCase):
    def setUp(self):
        self.vrf = VRF(generate_keypair(b"verify-seed").secret_key)
        self.out, self.proof = self.vrf.prove("msg")

    def test_happy_path(self):
        self.assertTrue(verify(self.vrf.public_key, "msg", self.out, self.proof))

    def test_wrong_input_fails(self):
        self.assertFalse(verify(self.vrf.public_key, "other", self.out, self.proof))

    def test_wrong_output_fails(self):
        self.assertFalse(
            verify(self.vrf.public_key, "msg", "f" * 64, self.proof)
        )

    def test_wrong_key_fails(self):
        other_pk = generate_keypair(b"other-key").public_key
        self.assertFalse(verify(other_pk, "msg", self.out, self.proof))

    def test_mismatched_proof_record_fails(self):
        # Proof record naming a different key than the caller claims.
        other = VRF(generate_keypair(b"other").secret_key)
        _, other_proof = other.prove("msg")
        self.assertFalse(verify(self.vrf.public_key, "msg", self.out, other_proof))

    def test_malformed_inputs_raise(self):
        with self.assertRaises(VRFError):
            verify("not-hex", "msg", self.out, self.proof)
        with self.assertRaises(VRFError):
            verify(self.vrf.public_key, "msg", "short", self.proof)
        with self.assertRaises(VRFError):
            verify(self.vrf.public_key, "msg", self.out, "not-a-proof")
        with self.assertRaises(VRFError):
            verify(self.vrf.public_key, 123, self.out, self.proof)


class TestRecheck(unittest.TestCase):
    def setUp(self):
        self.vrf = VRF(generate_keypair(b"recheck-seed").secret_key)

    def test_recheck_honest_proof(self):
        _, proof = self.vrf.prove("x")
        self.assertTrue(self.vrf.recheck(proof))

    def test_recheck_tampered_tag_fails(self):
        _, proof = self.vrf.prove("x")
        tampered = VRFProof(
            public_key=proof.public_key,
            input_digest=proof.input_digest,
            output_digest=proof.output_digest,
            proof_tag="a" * 64,
        )
        self.assertFalse(self.vrf.recheck(tampered))

    def test_recheck_wrong_key_fails(self):
        _, proof = self.vrf.prove("x")
        other = VRF(generate_keypair(b"other").secret_key)
        self.assertFalse(other.recheck(proof))

    def test_recheck_rejects_non_proof(self):
        with self.assertRaises(VRFError):
            self.vrf.recheck({"not": "a proof"})

    def test_attacker_with_pk_cannot_mint_recheckable_tag(self):
        # Simulation boundary made concrete: knowing pk is not enough.
        pk = self.vrf.public_key
        _, proof = self.vrf.prove("victim-input")
        forged = VRFProof(
            public_key=pk,
            input_digest=proof.input_digest,
            output_digest=proof.output_digest,
            proof_tag="b" * 64,  # attacker guesses; cannot derive sk-bound tag
        )
        self.assertFalse(self.vrf.recheck(forged))
        # Structural verify of the honest proof still holds.
        self.assertTrue(verify(pk, "victim-input", proof.output_digest, proof))


class TestAuditEvent(unittest.TestCase):
    def test_shape(self):
        kp = generate_keypair(b"audit")
        ev = vrf_audit_event("proved", kp.public_key, 7)
        self.assertEqual(ev["format"], "audit.ndjson/1")
        self.assertEqual(ev["version"], VERSION)
        self.assertEqual(ev["schema"], SCHEMA)
        self.assertEqual(ev["kind"], "proved")
        self.assertEqual(ev["seq"], 7)

    def test_extra(self):
        kp = generate_keypair(b"audit")
        ev = vrf_audit_event("verified", kp.public_key, 0, extra={"ok": True})
        self.assertEqual(ev["extra"], {"ok": True})

    def test_reject_bad_kind(self):
        kp = generate_keypair(b"audit")
        with self.assertRaises(VRFError):
            vrf_audit_event("bogus", kp.public_key, 0)

    def test_reject_bad_seq(self):
        kp = generate_keypair(b"audit")
        for bad in (-1, True, "0", None):
            with self.assertRaises(VRFError, msg=repr(bad)):
                vrf_audit_event("proved", kp.public_key, bad)


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        import vrf_interface

        vrf_interface.main()


if __name__ == "__main__":
    unittest.main()
