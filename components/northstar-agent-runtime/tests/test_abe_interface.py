"""Tests for abe_interface: policy-based encryption (simulated)."""

import unittest

from abe_interface import (
    ABE,
    ABE_VERSION,
    SCHEMA_PIN,
    ABEError,
    Ciphertext,
    CiphertextIntegrityError,
    Policy,
    PolicyError,
    PolicyNotSatisfiedError,
    PublicParams,
    SecretKey,
    UnknownCiphertextError,
    UnknownKeyError,
    abe_audit_event,
    parse_policy,
    policy_satisfied,
)


def fresh_abe() -> ABE:
    abe = ABE()
    abe.setup()
    return abe


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(ABE_VERSION, "abe-interface.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.abe-interface.v1")


class TestSetup(unittest.TestCase):
    def test_setup_returns_public_params(self):
        abe = ABE()
        params = abe.setup()
        self.assertIsInstance(params, PublicParams)
        self.assertTrue(params.params_id.startswith("sha256:"))
        self.assertEqual(params.version, ABE_VERSION)
        d = params.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)

    def test_setup_twice_raises(self):
        abe = fresh_abe()
        with self.assertRaises(ABEError):
            abe.setup()

    def test_keygen_before_setup_raises(self):
        abe = ABE()
        with self.assertRaises(ABEError):
            abe.keygen(["a"])

    def test_encrypt_before_setup_raises(self):
        abe = ABE()
        with self.assertRaises(ABEError):
            abe.encrypt("a", b"x")


class TestKeygen(unittest.TestCase):
    def test_keygen_happy_path(self):
        abe = fresh_abe()
        key = abe.keygen(["a", "b"])
        self.assertIsInstance(key, SecretKey)
        self.assertEqual(key.attributes, frozenset({"a", "b"}))
        self.assertTrue(key.key_id.startswith("sha256:"))
        d = key.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["attributes"], ["a", "b"])

    def test_keygen_dedupes_attributes(self):
        abe = fresh_abe()
        key = abe.keygen(["a", "a", "b"])
        self.assertEqual(key.attributes, frozenset({"a", "b"}))

    def test_keygen_empty_attributes_rejected(self):
        abe = fresh_abe()
        with self.assertRaises(ValueError):
            abe.keygen([])

    def test_keygen_bad_attribute_types(self):
        abe = fresh_abe()
        for bad in (["a", 1], ["a", True], ["a", None], ["a", b"b"]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                abe.keygen(bad)

    def test_keygen_empty_attribute_string(self):
        abe = fresh_abe()
        with self.assertRaises(ValueError):
            abe.keygen([""])

    def test_keygen_illegal_characters(self):
        abe = fresh_abe()
        with self.assertRaises(ValueError):
            abe.keygen(["a b"])

    def test_keygen_not_a_sequence(self):
        abe = fresh_abe()
        with self.assertRaises(TypeError):
            abe.keygen("ab")  # a bare str is not an attribute list

    def test_keygen_deterministic(self):
        abe = fresh_abe()
        k1 = abe.keygen(["a", "b"])
        k2 = abe.keygen(["b", "a"])
        self.assertEqual(k1.key_id, k2.key_id)


class TestPolicyParser(unittest.TestCase):
    def test_atom(self):
        p = parse_policy("clearance:top-secret")
        self.assertEqual(p.op, "atom")
        self.assertEqual(p.name, "clearance:top-secret")

    def test_and_or_precedence(self):
        p = parse_policy("a | b & c")
        self.assertEqual(p.op, "or")
        # b & c binds tighter
        self.assertEqual(p.children[1].op, "and")

    def test_parens(self):
        p = parse_policy("(a | b) & c")
        self.assertEqual(p.op, "and")
        self.assertEqual(p.children[0].op, "or")

    def test_threshold(self):
        p = parse_policy("2of(a, b, c)")
        self.assertEqual(p.op, "threshold")
        self.assertEqual(p.k, 2)
        self.assertEqual(len(p.children), 3)

    def test_threshold_one_folds_to_or(self):
        p = parse_policy("1of(a, b)")
        self.assertEqual(p.op, "or")

    def test_threshold_all_folds_to_and(self):
        p = parse_policy("2of(a, b)")
        self.assertEqual(p.op, "and")

    def test_canonical_form_sorts_children(self):
        p1 = parse_policy("b & a")
        p2 = parse_policy("a & b")
        self.assertEqual(p1.to_string(), p2.to_string())
        self.assertEqual(p1, p2)

    def test_empty_policy_rejected(self):
        with self.assertRaises(PolicyError):
            parse_policy("   ")

    def test_trailing_tokens_rejected(self):
        with self.assertRaises(PolicyError):
            parse_policy("a b")

    def test_unbalanced_paren_rejected(self):
        with self.assertRaises(PolicyError):
            parse_policy("(a & b")

    def test_threshold_k_too_big(self):
        with self.assertRaises(PolicyError):
            parse_policy("3of(a, b)")

    def test_illegal_character_rejected(self):
        with self.assertRaises(PolicyError):
            parse_policy("a $ b")

    def test_non_string_policy(self):
        with self.assertRaises(TypeError):
            parse_policy(123)  # type: ignore[arg-type]

    def test_policy_as_dict(self):
        p = parse_policy("a & b")
        d = p.as_dict()
        self.assertEqual(d["op"], "and")
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(len(d["children"]), 2)


class TestPolicySatisfied(unittest.TestCase):
    def test_atom(self):
        p = parse_policy("a")
        self.assertTrue(policy_satisfied(p, frozenset({"a", "b"})))
        self.assertFalse(policy_satisfied(p, frozenset({"b"})))

    def test_and(self):
        p = parse_policy("a & b")
        self.assertTrue(policy_satisfied(p, frozenset({"a", "b"})))
        self.assertFalse(policy_satisfied(p, frozenset({"a"})))

    def test_or(self):
        p = parse_policy("a | b")
        self.assertTrue(policy_satisfied(p, frozenset({"b"})))
        self.assertFalse(policy_satisfied(p, frozenset({"c"})))

    def test_threshold(self):
        p = parse_policy("2of(a, b, c)")
        self.assertTrue(policy_satisfied(p, frozenset({"a", "c"})))
        self.assertFalse(policy_satisfied(p, frozenset({"a"})))

    def test_nested(self):
        p = parse_policy("a & (b | c)")
        self.assertTrue(policy_satisfied(p, frozenset({"a", "c"})))
        self.assertFalse(policy_satisfied(p, frozenset({"a"})))
        self.assertFalse(policy_satisfied(p, frozenset({"b", "c"})))

    def test_bad_types(self):
        with self.assertRaises(TypeError):
            policy_satisfied("a", frozenset({"a"}))  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            policy_satisfied(parse_policy("a"), {"a"})  # type: ignore[arg-type]


class TestEncrypt(unittest.TestCase):
    def test_encrypt_happy_path(self):
        abe = fresh_abe()
        ct = abe.encrypt("a & b", b"secret")
        self.assertIsInstance(ct, Ciphertext)
        self.assertTrue(ct.ct_id.startswith("sha256:"))
        self.assertEqual(ct.policy.to_string(), "a & b")
        # The blob must not contain the plaintext (simulated wrap).
        self.assertNotIn(b"secret", ct.blob)
        d = ct.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)

    def test_encrypt_accepts_policy_object(self):
        abe = fresh_abe()
        ct = abe.encrypt(parse_policy("a | b"), b"x")
        self.assertEqual(ct.policy.op, "or")

    def test_encrypt_rejects_str_data(self):
        abe = fresh_abe()
        with self.assertRaises(TypeError):
            abe.encrypt("a", "not bytes")  # type: ignore[arg-type]

    def test_encrypt_rejects_bad_policy_type(self):
        abe = fresh_abe()
        with self.assertRaises(TypeError):
            abe.encrypt(123, b"x")  # type: ignore[arg-type]

    def test_encrypt_rejects_bad_policy_text(self):
        abe = fresh_abe()
        with self.assertRaises(PolicyError):
            abe.encrypt("(a", b"x")

    def test_encrypt_empty_data(self):
        abe = fresh_abe()
        ct = abe.encrypt("a", b"")
        key = abe.keygen(["a"])
        self.assertEqual(abe.decrypt(key, ct), b"")

    def test_encrypt_deterministic(self):
        abe = fresh_abe()
        ct1 = abe.encrypt("a", b"x")
        # A second instance mints different ids (distinct master secret).
        abe2 = fresh_abe()
        ct2 = abe2.encrypt("a", b"x")
        self.assertNotEqual(ct1.ct_id, ct2.ct_id)
        self.assertNotEqual(ct1.blob, ct2.blob)


class TestDecrypt(unittest.TestCase):
    def test_roundtrip_and_policy(self):
        abe = fresh_abe()
        key = abe.keygen(["a", "b"])
        ct = abe.encrypt("a & b", b"payload")
        self.assertEqual(abe.decrypt(key, ct), b"payload")

    def test_or_policy_single_branch(self):
        abe = fresh_abe()
        key = abe.keygen(["b"])
        ct = abe.encrypt("a | b", b"payload")
        self.assertEqual(abe.decrypt(key, ct), b"payload")

    def test_threshold_policy(self):
        abe = fresh_abe()
        key = abe.keygen(["a", "c"])
        ct = abe.encrypt("2of(a, b, c)", b"payload")
        self.assertEqual(abe.decrypt(key, ct), b"payload")

    def test_unsatisfied_policy_raises(self):
        abe = fresh_abe()
        key = abe.keygen(["a"])
        ct = abe.encrypt("a & b", b"payload")
        with self.assertRaises(PolicyNotSatisfiedError):
            abe.decrypt(key, ct)

    def test_unsatisfied_threshold_raises(self):
        abe = fresh_abe()
        key = abe.keygen(["a"])
        ct = abe.encrypt("2of(a, b, c)", b"payload")
        with self.assertRaises(PolicyNotSatisfiedError):
            abe.decrypt(key, ct)

    def test_unknown_key_raises(self):
        abe1 = fresh_abe()
        abe2 = fresh_abe()
        key2 = abe2.keygen(["a"])
        ct = abe1.encrypt("a", b"payload")
        with self.assertRaises(UnknownKeyError):
            abe1.decrypt(key2, ct)

    def test_unknown_ciphertext_raises(self):
        abe1 = fresh_abe()
        abe2 = fresh_abe()
        key = abe1.keygen(["a"])
        ct2 = abe2.encrypt("a", b"payload")
        with self.assertRaises(UnknownCiphertextError):
            abe1.decrypt(key, ct2)

    def test_tampered_blob_raises(self):
        abe = fresh_abe()
        key = abe.keygen(["a"])
        ct = abe.encrypt("a", b"payload")
        bad = Ciphertext(
            ct_id=ct.ct_id, policy=ct.policy,
            policy_digest=ct.policy_digest,
            blob=b"\x00" * len(ct.blob),
            data_digest=ct.data_digest, params_id=ct.params_id)
        with self.assertRaises(CiphertextIntegrityError):
            abe.decrypt(key, bad)

    def test_tampered_policy_pin_raises(self):
        abe = fresh_abe()
        key = abe.keygen(["a", "b"])
        ct = abe.encrypt("a", b"payload")
        # Weaken the policy but keep the pin: digest check must fail.
        weak = Ciphertext(
            ct_id=ct.ct_id, policy=parse_policy("a | b"),
            policy_digest=ct.policy_digest, blob=ct.blob,
            data_digest=ct.data_digest, params_id=ct.params_id)
        with self.assertRaises(CiphertextIntegrityError):
            abe.decrypt(key, weak)

    def test_bad_arg_types(self):
        abe = fresh_abe()
        key = abe.keygen(["a"])
        ct = abe.encrypt("a", b"x")
        with self.assertRaises(TypeError):
            abe.decrypt("nope", ct)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            abe.decrypt(key, "nope")  # type: ignore[arg-type]

    def test_decrypt_before_setup_raises(self):
        abe = ABE()
        with self.assertRaises(ABEError):
            abe.decrypt(SecretKey(key_id="sha256:x",
                                 attributes=frozenset({"a"}),
                                 params_id="sha256:y"),
                        Ciphertext(ct_id="sha256:z",
                                   policy=parse_policy("a"),
                                   policy_digest="sha256:p", blob=b"",
                                   data_digest="sha256:d",
                                   params_id="sha256:y"))

    def test_large_data_roundtrip(self):
        abe = fresh_abe()
        key = abe.keygen(["a"])
        data = bytes(range(256)) * 100
        ct = abe.encrypt("a", data)
        self.assertEqual(abe.decrypt(key, ct), data)


class TestViews(unittest.TestCase):
    def test_issued_keys_and_ciphertexts(self):
        abe = fresh_abe()
        k = abe.keygen(["a"])
        ct = abe.encrypt("a", b"x")
        self.assertEqual(abe.issued_keys(), (k.key_id,))
        self.assertEqual(abe.minted_ciphertexts(), (ct.ct_id,))


class TestAuditEvent(unittest.TestCase):
    def test_shapes(self):
        abe = fresh_abe()
        key = abe.keygen(["a"])
        ct = abe.encrypt("a", b"x")
        ev = abe_audit_event("decrypted", 7, key=key, ciphertext=ct,
                             satisfied=True)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["module"], SCHEMA_PIN)
        self.assertEqual(ev["kind"], "decrypted")
        self.assertEqual(ev["audit_seq"], 7)
        self.assertEqual(ev["key_id"], key.key_id)
        self.assertEqual(ev["attributes"], ["a"])
        self.assertEqual(ev["ct_id"], ct.ct_id)
        self.assertEqual(ev["policy"], "a")
        self.assertTrue(ev["satisfied"])

    def test_setup_event(self):
        ev = abe_audit_event("setup", 0)
        self.assertEqual(ev["kind"], "setup")

    def test_bad_kind(self):
        with self.assertRaises(ValueError):
            abe_audit_event("bogus", 0)

    def test_bad_seq(self):
        with self.assertRaises(TypeError):
            abe_audit_event("setup", True)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            abe_audit_event("setup", -1)

    def test_bad_satisfied_type(self):
        with self.assertRaises(TypeError):
            abe_audit_event("decrypted", 0, satisfied="yes")  # type: ignore[arg-type]


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        from abe_interface import main
        main()


if __name__ == "__main__":
    unittest.main()
