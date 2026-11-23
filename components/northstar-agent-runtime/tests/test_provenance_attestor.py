"""Tests for provenance_attestor: SLSA-shaped provenance bookkeeping."""

import ast
import dataclasses
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from provenance_attestor import (  # noqa: E402
    PROVENANCE_ATTESTOR_VERSION,
    SCHEMA_PIN,
    AUDIT_SCHEMA,
    STATEMENT_TYPE,
    PREDICATE_TYPE,
    PAYLOAD_TYPE,
    Attestation,
    ProvenanceAttestor,
    ProvenanceError,
    UnknownKeyError,
    DuplicateKeyError,
    UnknownAttestationError,
    UnknownPolicyError,
    DuplicatePolicyError,
    BadDigestError,
    BadBuilderError,
    BadPolicyError,
    SeqOrderError,
    provenance_attestor_audit_event,
    main,
)

SEED = b"test-seed-0123456789abcdef"
DIGEST = "sha256:" + "aa" * 32
MAT_DIGEST = "sha256:" + "bb" * 32
BUILDER = "https://github.com/actions/runner@v1"
BUILD_TYPE = "https://slsa.dev/buildType/go@v1"


def _fresh(**kw):
    return ProvenanceAttestor(seed=SEED, **kw)


def _attestor_with_key(seq_start=0):
    a = _fresh()
    a.register_key("k1", seq=seq_start)
    return a


def _attest(a, seq=1, **kw):
    params = dict(artifact_name="app-1.0.tgz", artifact_digest=DIGEST,
                  builder_id=BUILDER, build_type=BUILD_TYPE,
                  materials=[("https://github.com/example/app", MAT_DIGEST)],
                  key_id="k1", slsa_level=2,
                  source_uri="https://github.com/example/app",
                  invocation_id="inv-9")
    params.update(kw)
    return a.attest(seq=seq, **params)


class TestPins(unittest.TestCase):
    def test_version_and_schema(self):
        self.assertEqual(PROVENANCE_ATTESTOR_VERSION, "provenance-attestor.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.provenance-attestor.v1")

    def test_statement_and_envelope_constants(self):
        self.assertEqual(STATEMENT_TYPE, "https://in-toto.io/Statement/v1")
        self.assertEqual(PREDICATE_TYPE, "https://slsa.dev/provenance/v1")
        self.assertEqual(PAYLOAD_TYPE, "application/vnd.in-toto+json")


class TestKeys(unittest.TestCase):
    def test_register_key_roundtrip(self):
        a = _fresh()
        rec = a.register_key("ci", seq=0)
        self.assertEqual(rec.key_id, "ci")
        self.assertTrue(rec.key_digest.startswith("sha256:"))
        self.assertEqual(rec.version, PROVENANCE_ATTESTOR_VERSION)
        self.assertEqual(a.key("ci"), rec)
        self.assertEqual(a.key_ids(), ("ci",))

    def test_register_key_duplicate_refused(self):
        a = _attestor_with_key()
        with self.assertRaises(DuplicateKeyError):
            a.register_key("k1", seq=1)

    def test_register_key_unknown_lookup(self):
        a = _fresh()
        with self.assertRaises(UnknownKeyError):
            a.key("ghost")

    def test_register_key_explicit_secret(self):
        a = ProvenanceAttestor()
        rec = a.register_key("s1", seq=0, secret=b"x" * 32)
        self.assertTrue(rec.key_digest.startswith("sha256:"))
        a2 = ProvenanceAttestor()
        with self.assertRaises(ProvenanceError):
            a2.register_key("s1", seq=0)  # no seed, no secret
        with self.assertRaises(ProvenanceError):
            a.register_key("s2", seq=1, secret=b"short")  # too short

    def test_key_record_has_no_secret(self):
        a = _attestor_with_key()
        rec = a.key("k1")
        d = rec.as_dict()
        self.assertNotIn("secret", d)
        self.assertNotIn("secret", str(d))


class TestAttest(unittest.TestCase):
    def test_attest_roundtrip_and_shape(self):
        a = _attestor_with_key()
        rec = _attest(a)
        self.assertEqual(rec.att_id, "att-1")
        self.assertEqual(rec.key_id, "k1")
        self.assertEqual(rec.slsa_level, 2)
        self.assertTrue(rec.statement_digest.startswith("sha256:"))
        self.assertTrue(rec.envelope_digest.startswith("sha256:"))
        stmt = rec.statement
        self.assertEqual(stmt["_type"], STATEMENT_TYPE)
        self.assertEqual(stmt["predicateType"], PREDICATE_TYPE)
        self.assertEqual(stmt["subject"][0]["digest"]["sha256"], "aa" * 32)
        self.assertEqual(stmt["predicate"]["runDetails"]["builder"]["id"], BUILDER)
        self.assertEqual(rec.envelope["payloadType"], PAYLOAD_TYPE)
        self.assertEqual(rec.envelope["signatures"][0]["keyid"], "k1")
        self.assertTrue(rec.verify_digest())
        self.assertEqual(a.attestation("att-1"), rec)

    def test_attest_digest_determinism(self):
        a1, a2 = _attestor_with_key(), _attestor_with_key()
        r1, r2 = _attest(a1), _attest(a2)
        self.assertEqual(r1.statement_digest, r2.statement_digest)
        self.assertEqual(r1.envelope_digest, r2.envelope_digest)

    def test_attest_ids_monotonic(self):
        a = _attestor_with_key()
        r1 = _attest(a, seq=1, artifact_name="a")
        r2 = _attest(a, seq=2, artifact_name="b")
        self.assertEqual((r1.att_id, r2.att_id), ("att-1", "att-2"))
        self.assertEqual(a.attestation_ids(), ("att-1", "att-2"))

    def test_attest_bad_digest(self):
        a = _attestor_with_key()
        with self.assertRaises(BadDigestError):
            _attest(a, artifact_digest="not-a-digest")

    def test_attest_bad_builder(self):
        a = _attestor_with_key()
        with self.assertRaises(BadBuilderError):
            _attest(a, builder_id="not-a-uri")

    def test_attest_bad_level(self):
        a = _attestor_with_key()
        with self.assertRaises(ProvenanceError):
            _attest(a, slsa_level=9)

    def test_attest_unknown_key(self):
        a = _attestor_with_key()
        with self.assertRaises(UnknownKeyError):
            _attest(a, key_id="ghost")

    def test_attest_seq_discipline(self):
        a = _attestor_with_key()
        with self.assertRaises(SeqOrderError):
            _attest(a, seq=0)  # rewind (key used seq 0)
        with self.assertRaises(ProvenanceError):
            _attest(a, seq=True)  # bool seq
        # failed mutation consumes its seq
        with self.assertRaises(BadDigestError):
            _attest(a, seq=1, artifact_digest="bad")
        with self.assertRaises(SeqOrderError):
            _attest(a, seq=1)


class TestVerify(unittest.TestCase):
    def test_verify_happy_path(self):
        a = _attestor_with_key()
        _attest(a)
        rep = a.verify("att-1", seq=2)
        self.assertTrue(rep.valid, rep.reasons)
        self.assertEqual(rep.reasons, ())
        self.assertIsNone(rep.policy_id)
        self.assertIsNone(rep.policy_ok)
        self.assertEqual(rep.key_id, "k1")

    def test_verify_unknown_attestation(self):
        a = _fresh()
        with self.assertRaises(UnknownAttestationError):
            a.verify("att-404", seq=0)

    def test_verify_tampered_payload(self):
        a = _attestor_with_key()
        rec = _attest(a)
        tampered = dataclasses.replace(
            rec, envelope={**rec.envelope, "payload": "e30"})
        a._attestations["att-1"] = tampered
        rep = a.verify("att-1", seq=2)
        self.assertFalse(rep.valid)
        self.assertIn("envelope-tampered", rep.reasons)
        self.assertIn("signature-invalid", rep.reasons)

    def test_verify_unknown_signing_key(self):
        a = _attestor_with_key()
        rec = _attest(a)
        env = dict(rec.envelope)
        env["signatures"] = [{"keyid": "ghost", "sig": "00" * 32}]
        ghost = dataclasses.replace(rec, envelope=env)
        a._attestations["att-1"] = ghost
        rep = a.verify("att-1", seq=2)
        self.assertFalse(rep.valid)
        self.assertIn("unknown-signing-key", rep.reasons)


class TestPolicy(unittest.TestCase):
    def test_policy_define_roundtrip(self):
        a = _attestor_with_key()
        pol = a.policy("prod", seq=1, trusted_builders=[BUILDER],
                       min_slsa_level=2,
                       expected_source_uri="https://github.com/example/app",
                       trusted_keys=["k1"], require_resolved_deps=True)
        self.assertEqual(pol.policy_id, "prod")
        self.assertEqual(pol.trusted_builders, (BUILDER,))
        self.assertEqual(pol.min_slsa_level, 2)
        self.assertTrue(pol.policy_digest.startswith("sha256:"))
        self.assertEqual(a.get_policy("prod"), pol)

    def test_policy_duplicate_refused(self):
        a = _attestor_with_key()
        a.policy("p", seq=1)
        with self.assertRaises(DuplicatePolicyError):
            a.policy("p", seq=2)

    def test_policy_unknown_lookup(self):
        a = _fresh()
        with self.assertRaises(UnknownPolicyError):
            a.get_policy("nope")

    def test_policy_trusted_key_must_be_registered(self):
        a = _attestor_with_key()
        with self.assertRaises(UnknownKeyError):
            a.policy("p", seq=1, trusted_keys=["ghost"])

    def test_policy_bad_builder_and_level(self):
        a = _fresh()
        with self.assertRaises(BadBuilderError):
            a.policy("p", seq=0, trusted_builders=["not-a-uri"])
        with self.assertRaises(ProvenanceError):
            a.policy("p", seq=1, min_slsa_level=7)
        with self.assertRaises(BadPolicyError):
            a.policy("p", seq=2, require_resolved_deps="yes")

    def test_verify_with_policy_pass(self):
        a = _attestor_with_key()
        _attest(a)
        a.policy("prod", seq=2, trusted_builders=[BUILDER], min_slsa_level=2,
                 expected_source_uri="https://github.com/example/app",
                 trusted_keys=["k1"], require_resolved_deps=True)
        rep = a.verify("att-1", seq=3, policy_name="prod")
        self.assertTrue(rep.valid, rep.reasons)
        self.assertTrue(rep.policy_ok)
        self.assertEqual(rep.policy_id, "prod")

    def test_verify_with_policy_fail(self):
        a = _attestor_with_key()
        _attest(a)
        a.policy("strict", seq=2,
                 trusted_builders=["https://other.example/builder"],
                 min_slsa_level=3,
                 expected_source_uri="https://other.example/src",
                 trusted_keys=["k1"])
        rep = a.verify("att-1", seq=3, policy_name="strict")
        self.assertFalse(rep.valid)
        self.assertFalse(rep.policy_ok)
        self.assertIn("builder-untrusted", rep.reasons)
        self.assertIn("level-too-low", rep.reasons)
        self.assertIn("source-uri-mismatch", rep.reasons)
        self.assertNotIn("key-untrusted", rep.reasons)

    def test_verify_key_untrusted(self):
        a = _fresh()
        a.register_key("k1", seq=0)
        a.register_key("k2", seq=1)
        a.attest("x", DIGEST, BUILDER, BUILD_TYPE, [], seq=2, key_id="k2")
        a.policy("p", seq=3, trusted_keys=["k1"])
        rep = a.verify("att-1", seq=4, policy_name="p")
        self.assertFalse(rep.valid)
        self.assertIn("key-untrusted", rep.reasons)

    def test_verify_no_resolved_deps(self):
        a = _attestor_with_key()
        _attest(a, materials=[])
        a.policy("p", seq=2, require_resolved_deps=True)
        rep = a.verify("att-1", seq=3, policy_name="p")
        self.assertFalse(rep.valid)
        self.assertIn("no-resolved-dependencies", rep.reasons)

    def test_verify_unknown_policy(self):
        a = _attestor_with_key()
        _attest(a)
        with self.assertRaises(UnknownPolicyError):
            a.verify("att-1", seq=2, policy_name="nope")


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        for kind in ("key-registered", "attested", "policy-defined",
                     "verified", "verification-failed", "rejected"):
            ev = provenance_attestor_audit_event(kind, 0, att_id="att-1")
            self.assertEqual(ev["schema"], AUDIT_SCHEMA)
            self.assertEqual(ev["module"], "provenance_attestor")
            self.assertEqual(ev["moduleVersion"], PROVENANCE_ATTESTOR_VERSION)
            self.assertEqual(ev["kind"], kind)

    def test_audit_unknown_kind_and_secret_ban(self):
        with self.assertRaises(ProvenanceError):
            provenance_attestor_audit_event("nope", 0)
        with self.assertRaises(ProvenanceError):
            provenance_attestor_audit_event("attested", 0, secret=b"x" * 16)
        with self.assertRaises(ProvenanceError):
            provenance_attestor_audit_event("attested", 0,
                                            statement={"a": 1})


class TestStdlibOnly(unittest.TestCase):
    def test_stdlib_only(self):
        tree = ast.parse(Path(__file__).resolve().parent.parent
                         .joinpath("provenance_attestor.py").read_text())
        allowed = {"base64", "hashlib", "hmac", "json", "re", "threading",
                   "dataclasses", "typing", "__future__"}
        found = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                found.add(node.module.split(".")[0])
        self.assertLessEqual(found, allowed, found - allowed)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        main()


if __name__ == "__main__":
    unittest.main()
