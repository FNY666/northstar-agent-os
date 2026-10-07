"""Targeted tests for threshold_sig.py."""

import ast
import dataclasses
import unittest
from pathlib import Path

from threshold_sig import (
    THRESHOLD_SIG_VERSION,
    SCHEMA_PIN,
    KeyShares,
    SignatureShare,
    ThresholdSignature,
    ThresholdSigError,
    combine,
    keygen,
    lagrange_coefficient,
    sign_share,
    threshold_sig_audit_event,
    verify,
    _G,
    _P,
    _Q,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(THRESHOLD_SIG_VERSION, "threshold-sig.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.threshold-sig.v1")


class TestGroupParams(unittest.TestCase):
    def test_safe_prime_shape(self):
        self.assertEqual(_P, 2 * _Q + 1)

    def test_generator_in_subgroup(self):
        self.assertEqual(pow(_G, _Q, _P), 1)
        self.assertNotEqual(_G % _P, 1)

    def test_field_size(self):
        self.assertEqual(_Q.bit_length(), 128)


class TestKeygen(unittest.TestCase):
    def test_happy_path(self):
        ks = keygen(5, 3, seed=b"t1")
        self.assertEqual(ks.n, 5)
        self.assertEqual(ks.t, 3)
        self.assertEqual(len(ks.shares), 5)
        self.assertEqual([pid for pid, _ in ks.shares], [1, 2, 3, 4, 5])

    def test_deterministic(self):
        a = keygen(4, 2, seed=b"same")
        b = keygen(4, 2, seed=b"same")
        self.assertEqual(a.as_dict(), b.as_dict())

    def test_different_seed_different_key(self):
        a = keygen(4, 2, seed=b"one")
        b = keygen(4, 2, seed=b"two")
        self.assertNotEqual(a.group_public, b.group_public)
        self.assertNotEqual(a.params_digest, b.params_digest)

    def test_group_public_matches_master(self):
        ks = keygen(3, 2, seed=b"gp")
        # Reconstruct master from t=2 shares via Lagrange at 0.
        s1 = ks.share_of(1)
        s2 = ks.share_of(2)
        lam1 = lagrange_coefficient(1, [1, 2])
        lam2 = lagrange_coefficient(2, [1, 2])
        master = (lam1 * s1 + lam2 * s2) % _Q
        self.assertEqual(pow(_G, master, _P),
                         int(ks.group_public, 16))

    def test_degenerate_1_of_1(self):
        ks = keygen(1, 1)
        sig = combine(ks, [sign_share(ks, 1, b"m", [1])])
        self.assertTrue(verify(ks, b"m", sig))

    def test_bad_n(self):
        for bad in (0, -1):
            with self.assertRaises(ValueError):
                keygen(bad, 1)
        for bad in (True, "3", 3.0, None):
            with self.assertRaises(TypeError):
                keygen(bad, 1)

    def test_bad_t(self):
        for bad in (0, -2, 4):  # t > n=3 also rejected
            with self.assertRaises(ValueError):
                keygen(3, bad)
        for bad in (True, "2", None):
            with self.assertRaises(TypeError):
                keygen(3, bad)

    def test_bad_seed(self):
        with self.assertRaises(TypeError):
            keygen(3, 2, seed="not-bytes")
        with self.assertRaises(TypeError):
            keygen(3, 2, seed=True)

    def test_share_of_unknown(self):
        ks = keygen(3, 2)
        with self.assertRaises(ThresholdSigError):
            ks.share_of(99)

    def test_records_frozen(self):
        ks = keygen(3, 2)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            ks.n = 9  # type: ignore

    def test_as_dict_shape(self):
        ks = keygen(3, 2, seed=b"d")
        d = ks.as_dict()
        self.assertEqual(d["version"], "threshold-sig.v1")
        self.assertEqual(d["schema"], "northstar.threshold-sig.v1")
        self.assertEqual(d["n"], 3)
        self.assertEqual(len(d["shares"]), 3)


class TestLagrange(unittest.TestCase):
    def test_known_values(self):
        # S = {1, 2}: lambda_1 = 2, lambda_2 = -1 (mod q).
        self.assertEqual(lagrange_coefficient(1, [1, 2]), 2)
        self.assertEqual(lagrange_coefficient(2, [1, 2]), _Q - 1)

    def test_reconstructs_constant(self):
        # f(x) = 7 + 5x + 3x^2; any 3 points recover 7.
        f = lambda x: (7 + 5 * x + 3 * x * x) % _Q
        for S in ([1, 2, 3], [2, 4, 5], [1, 3, 5]):
            total = sum(f(i) * lagrange_coefficient(i, S) for i in S) % _Q
            self.assertEqual(total, 7)

    def test_unknown_participant(self):
        with self.assertRaises(ThresholdSigError):
            lagrange_coefficient(9, [1, 2])

    def test_duplicate_ids(self):
        with self.assertRaises(ThresholdSigError):
            lagrange_coefficient(1, [1, 1, 2])


class TestSignShare(unittest.TestCase):
    def setUp(self):
        self.ks = keygen(5, 3, seed=b"sign")

    def test_happy_path(self):
        s = sign_share(self.ks, 2, b"hello", [1, 2, 3])
        self.assertEqual(s.participant_id, 2)
        self.assertEqual(s.signer_ids, (1, 2, 3))
        self.assertTrue(s.message_digest.startswith("sha256:"))

    def test_deterministic(self):
        a = sign_share(self.ks, 1, b"m", [1, 2, 3])
        b = sign_share(self.ks, 1, b"m", [1, 2, 3])
        self.assertEqual(a.as_dict(), b.as_dict())

    def test_nonce_bound_to_signer_set(self):
        a = sign_share(self.ks, 1, b"m", [1, 2, 3])
        b = sign_share(self.ks, 1, b"m", [1, 2, 4])
        self.assertNotEqual(a.z, b.z)

    def test_nonce_bound_to_message(self):
        a = sign_share(self.ks, 1, b"m1", [1, 2, 3])
        b = sign_share(self.ks, 1, b"m2", [1, 2, 3])
        self.assertNotEqual(a.nonce_commitment, b.nonce_commitment)

    def test_str_message(self):
        s = sign_share(self.ks, 1, "text", [1, 2, 3])
        self.assertTrue(s.message_digest.startswith("sha256:"))

    def test_str_bytes_type_tagged(self):
        a = sign_share(self.ks, 1, "m", [1, 2, 3])
        b = sign_share(self.ks, 1, b"m", [1, 2, 3])
        self.assertNotEqual(a.message_digest, b.message_digest)

    def test_participant_not_in_set(self):
        with self.assertRaises(ThresholdSigError):
            sign_share(self.ks, 4, b"m", [1, 2, 3])

    def test_unknown_participant(self):
        with self.assertRaises(ThresholdSigError):
            sign_share(self.ks, 99, b"m", [1, 99])

    def test_signer_out_of_range(self):
        with self.assertRaises(ThresholdSigError):
            sign_share(self.ks, 1, b"m", [1, 2, 6])

    def test_duplicate_signer_ids(self):
        with self.assertRaises(ThresholdSigError):
            sign_share(self.ks, 1, b"m", [1, 1, 2])

    def test_empty_signer_ids(self):
        with self.assertRaises(ValueError):
            sign_share(self.ks, 1, b"m", [])

    def test_empty_message(self):
        with self.assertRaises(ValueError):
            sign_share(self.ks, 1, b"", [1, 2, 3])
        with self.assertRaises(ValueError):
            sign_share(self.ks, 1, "", [1, 2, 3])

    def test_bad_message_type(self):
        for bad in (123, None, True, ["m"]):
            with self.assertRaises(TypeError):
                sign_share(self.ks, 1, bad, [1, 2, 3])

    def test_bad_shares_type(self):
        with self.assertRaises(TypeError):
            sign_share("nope", 1, b"m", [1, 2, 3])

    def test_share_frozen(self):
        s = sign_share(self.ks, 1, b"m", [1, 2, 3])
        with self.assertRaises(dataclasses.FrozenInstanceError):
            s.z = "00"  # type: ignore


class TestCombineVerify(unittest.TestCase):
    def setUp(self):
        self.ks = keygen(5, 3, seed=b"cv")

    def _sign(self, msg, signers):
        return [sign_share(self.ks, pid, msg, signers) for pid in signers]

    def test_full_flow_verifies(self):
        parts = self._sign(b"payload", [1, 2, 3])
        sig = combine(self.ks, parts)
        self.assertTrue(verify(self.ks, b"payload", sig))

    def test_more_than_t_verifies(self):
        parts = self._sign(b"payload", [1, 2, 3, 4, 5])
        sig = combine(self.ks, parts)
        self.assertTrue(verify(self.ks, b"payload", sig))

    def test_any_subset_of_t_verifies(self):
        parts = self._sign(b"payload", [2, 4, 5])
        sig = combine(self.ks, parts)
        self.assertTrue(verify(self.ks, b"payload", sig))

    def test_fewer_than_t_refused(self):
        parts = self._sign(b"payload", [1, 2])
        with self.assertRaises(ThresholdSigError):
            combine(self.ks, parts)

    def test_tampered_message_fails(self):
        sig = combine(self.ks, self._sign(b"payload", [1, 2, 3]))
        self.assertFalse(verify(self.ks, b"tampered", sig))

    def test_tampered_z_fails(self):
        sig = combine(self.ks, self._sign(b"payload", [1, 2, 3]))
        bad = ThresholdSignature(
            r=sig.r,
            z=format((int(sig.z, 16) + 1) % _Q, "064x"),
            signer_ids=sig.signer_ids,
            message_digest=sig.message_digest,
            params_digest=sig.params_digest,
        )
        self.assertFalse(verify(self.ks, b"payload", bad))

    def test_tampered_r_fails(self):
        sig = combine(self.ks, self._sign(b"payload", [1, 2, 3]))
        bad = ThresholdSignature(
            r=format((int(sig.r, 16) + 1) % _P, "066x"),
            z=sig.z,
            signer_ids=sig.signer_ids,
            message_digest=sig.message_digest,
            params_digest=sig.params_digest,
        )
        self.assertFalse(verify(self.ks, b"payload", bad))

    def test_wrong_key_fails(self):
        other = keygen(5, 3, seed=b"other-key")
        sig = combine(self.ks, self._sign(b"payload", [1, 2, 3]))
        self.assertFalse(verify(other, b"payload", sig))

    def test_duplicate_share_refused(self):
        parts = self._sign(b"payload", [1, 2, 3])
        with self.assertRaises(ThresholdSigError):
            combine(self.ks, parts + [parts[0]])

    def test_mixed_signer_sets_refused(self):
        a = self._sign(b"payload", [1, 2, 3])
        b = self._sign(b"payload", [1, 2, 4])
        with self.assertRaises(ThresholdSigError):
            combine(self.ks, a[:2] + b[2:])

    def test_mixed_messages_refused(self):
        a = self._sign(b"m1", [1, 2, 3])
        b = self._sign(b"m2", [1, 2, 3])
        with self.assertRaises(ThresholdSigError):
            combine(self.ks, a[:2] + [b[2]])

    def test_share_set_mismatch_refused(self):
        # Shares declare signers [1,2,3] but only two supplied.
        parts = self._sign(b"payload", [1, 2, 3])
        with self.assertRaises(ThresholdSigError):
            combine(self.ks, parts[:2])

    def test_empty_shares(self):
        with self.assertRaises(ValueError):
            combine(self.ks, [])

    def test_bad_types_raise(self):
        sig = combine(self.ks, self._sign(b"m", [1, 2, 3]))
        with self.assertRaises(TypeError):
            verify("nope", b"m", sig)
        with self.assertRaises(TypeError):
            verify(self.ks, b"m", "nope")
        with self.assertRaises(TypeError):
            verify(self.ks, 123, sig)

    def test_signature_frozen(self):
        sig = combine(self.ks, self._sign(b"m", [1, 2, 3]))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            sig.z = "00"  # type: ignore

    def test_signature_as_dict(self):
        sig = combine(self.ks, self._sign(b"m", [1, 2, 3]))
        d = sig.as_dict()
        self.assertEqual(d["schema"], "northstar.threshold-sig.v1")
        self.assertEqual(list(d["signer_ids"]), [1, 2, 3])


class TestAuditEvent(unittest.TestCase):
    def test_shape(self):
        e = threshold_sig_audit_event("combined", 7,
                                      message_digest="sha256:ab",
                                      params_digest="sha256:cd")
        self.assertEqual(e["format"], "audit.ndjson/1")
        self.assertEqual(e["kind"], "threshold-sig-combined")
        self.assertEqual(e["seq"], 7)
        self.assertEqual(e["message_digest"], "sha256:ab")

    def test_all_kinds(self):
        for kind in ("keygen", "share-signed", "combined",
                     "verified", "rejected"):
            e = threshold_sig_audit_event(kind, 0)
            self.assertEqual(e["kind"], f"threshold-sig-{kind}")

    def test_bad_kind(self):
        with self.assertRaises(ValueError):
            threshold_sig_audit_event("bogus", 0)

    def test_bad_seq(self):
        with self.assertRaises(TypeError):
            threshold_sig_audit_event("combined", True)
        with self.assertRaises(ValueError):
            threshold_sig_audit_event("combined", -1)


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        import threshold_sig
        threshold_sig.main()


class TestStdlibOnly(unittest.TestCase):
    def test_no_third_party_imports(self):
        src = Path(__file__).resolve().parent.parent / "threshold_sig.py"
        tree = ast.parse(src.read_text())
        allowed = {"hashlib", "hmac", "dataclasses", "typing", "__future__"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(node.module.split(".")[0], allowed)


if __name__ == "__main__":
    unittest.main()
