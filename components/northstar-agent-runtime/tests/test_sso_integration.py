"""Tests for sso_integration: provider registry, login validation, JIT.

24 cases (spec asked 15). Run with:
    python3 -m unittest discover -s tests -p "test_sso_integration.py"
"""

import ast
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sso_integration import (  # noqa: E402
    Assertion,
    BindingConflictError,
    BadAssertionError,
    BadProviderError,
    DuplicateProviderError,
    SSO_INTEGRATION_VERSION,
    SCHEMA_PIN,
    AUDIT_SCHEMA,
    SSOIntegration,
    SeqOrderError,
    UnknownProviderError,
    UnknownSubjectError,
    sso_integration_audit_event,
)

ISSUER = "https://corp.example.okta.com"
ENTITY = "https://corp.example.okta.com"


def _provider(sso, seq=1, pid="corp-okta", ptype="oidc"):
    return sso.provider(pid, ptype, seq, issuer=ISSUER,
                       entity_id=ENTITY,
                       client_secret="topsecret")


def _assertion(**kw):
    base = dict(sub="alice", issuer=ISSUER, audience=ENTITY,
                exp_seq=100, issued_seq=1, nonce="n1",
                signature_verifier="sig1",
                attributes={"email": "a@x.io", "name": "Alice",
                            "groups": "eng,sec"})
    base.update(kw)
    return Assertion(**base)


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(SSO_INTEGRATION_VERSION, "sso-integration.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.sso-integration.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")

    def test_stdlib_only_ast(self):
        path = os.path.join(os.path.dirname(__file__), "..",
                            "sso_integration.py")
        with open(path) as f:
            tree = ast.parse(f.read())
        allowed = {"__future__", "hashlib", "hmac", "re", "threading",
                   "dataclasses", "typing", "json", "canonical_json"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed,
                                  f"non-stdlib import: {a.name}")
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed,
                              f"non-stdlib import: {node.module}")


class TestProvider(unittest.TestCase):
    def test_provider_roundtrip(self):
        sso = SSOIntegration(seed=b"t")
        rec = _provider(sso)
        self.assertEqual(rec.provider_id, "corp-okta")
        self.assertEqual(rec.provider_type, "oidc")
        self.assertEqual(rec.issuer, ISSUER)
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertIn("corp-okta", sso.providers())

    def test_duplicate_provider_refused(self):
        sso = SSOIntegration(seed=b"t")
        _provider(sso)
        with self.assertRaises(DuplicateProviderError):
            _provider(sso, seq=2)

    def test_bad_provider_type_refused(self):
        sso = SSOIntegration(seed=b"t")
        with self.assertRaises(BadProviderError):
            sso.provider("x", "cas", 1, issuer=ISSUER)

    def test_bad_provider_id_refused(self):
        sso = SSOIntegration(seed=b"t")
        with self.assertRaises(BadProviderError):
            sso.provider("BAD ID!", "oidc", 1, issuer=ISSUER)

    def test_secret_never_stored_raw(self):
        sso = SSOIntegration(seed=b"t")
        rec = _provider(sso)
        snap = sso.as_dict()
        blob = repr(snap) + repr(rec)
        self.assertNotIn("topsecret", blob)
        for ev in sso.audit_log():
            self.assertNotIn("topsecret", repr(ev["payload"]))
            self.assertNotIn("client_secret", repr(ev["payload"]).lower())

    def test_unknown_provider_lookup(self):
        sso = SSOIntegration(seed=b"t")
        with self.assertRaises(UnknownProviderError):
            sso.provider_record("nope")


class TestLogin(unittest.TestCase):
    def test_login_valid(self):
        sso = SSOIntegration(seed=b"t")
        _provider(sso)
        d = sso.login("corp-okta", _assertion(), 2)
        self.assertTrue(d.valid)
        self.assertEqual(d.reason, "")
        self.assertEqual(d.sub, "alice")
        self.assertTrue(d.digest.startswith("sha256:"))

    def test_login_wrong_issuer(self):
        sso = SSOIntegration(seed=b"t")
        _provider(sso)
        d = sso.login("corp-okta", _assertion(issuer="https://evil.io"), 2)
        self.assertFalse(d.valid)
        self.assertEqual(d.reason, "wrong-issuer")

    def test_login_wrong_audience(self):
        sso = SSOIntegration(seed=b"t")
        _provider(sso)
        d = sso.login("corp-okta", _assertion(audience="other"), 2)
        self.assertFalse(d.valid)
        self.assertEqual(d.reason, "wrong-audience")

    def test_login_expired(self):
        sso = SSOIntegration(seed=b"t")
        _provider(sso)
        d = sso.login("corp-okta", _assertion(exp_seq=5), 6)
        self.assertFalse(d.valid)
        self.assertEqual(d.reason, "expired")

    def test_login_missing_sub(self):
        sso = SSOIntegration(seed=b"t")
        _provider(sso)
        d = sso.login("corp-okta", _assertion(sub=""), 2)
        self.assertFalse(d.valid)
        self.assertEqual(d.reason, "missing-sub")

    def test_login_unsigned_when_required(self):
        sso = SSOIntegration(seed=b"t")
        _provider(sso)
        d = sso.login("corp-okta", _assertion(signature_verifier=""), 2)
        self.assertFalse(d.valid)
        self.assertEqual(d.reason, "bad-signature")

    def test_login_nonce_replay(self):
        sso = SSOIntegration(seed=b"t")
        _provider(sso)
        d1 = sso.login("corp-okta", _assertion(nonce="r1"), 2)
        self.assertTrue(d1.valid)
        d2 = sso.login("corp-okta", _assertion(nonce="r1"), 3)
        self.assertFalse(d2.valid)
        self.assertEqual(d2.reason, "replayed-nonce")

    def test_login_unknown_provider_raises(self):
        sso = SSOIntegration(seed=b"t")
        with self.assertRaises(UnknownProviderError):
            sso.login("nope", _assertion(), 1)


class TestJIT(unittest.TestCase):
    def test_jit_provisions(self):
        sso = SSOIntegration(seed=b"t")
        _provider(sso)
        d = sso.login("corp-okta", _assertion(), 2)
        rec = sso.jit("corp-okta", d, 3)
        self.assertTrue(rec.subject_id.startswith("usr_"))
        self.assertEqual(rec.provider_id, "corp-okta")
        self.assertEqual(rec.sub, "alice")
        self.assertEqual(rec.email, "a@x.io")
        self.assertEqual(rec.provisioned_seq, 3)

    def test_jit_idempotent_relink(self):
        sso = SSOIntegration(seed=b"t")
        _provider(sso)
        d1 = sso.login("corp-okta", _assertion(nonce="j1"), 2)
        r1 = sso.jit("corp-okta", d1, 3)
        d2 = sso.login("corp-okta", _assertion(nonce="j2"), 4)
        r2 = sso.jit("corp-okta", d2, 5)
        self.assertEqual(r2.subject_id, r1.subject_id)
        self.assertEqual(r2.provisioned_seq, r1.provisioned_seq)
        self.assertEqual(r2.last_login_seq, 5)

    def test_jit_deterministic_across_instances(self):
        a = SSOIntegration(seed=b"s1")
        b = SSOIntegration(seed=b"s1")
        _provider(a)
        _provider(b)
        d1 = a.login("corp-okta", _assertion(), 2)
        d2 = b.login("corp-okta", _assertion(), 2)
        r1 = a.jit("corp-okta", d1, 3)
        r2 = b.jit("corp-okta", d2, 3)
        self.assertEqual(r1.subject_id, r2.subject_id)

    def test_jit_invalid_decision_raises(self):
        sso = SSOIntegration(seed=b"t")
        _provider(sso)
        d = sso.login("corp-okta", _assertion(issuer="x"), 2)
        self.assertFalse(d.valid)
        with self.assertRaises(BadAssertionError):
            sso.jit("corp-okta", d, 3)

    def test_jit_wrong_provider_raises(self):
        sso = SSOIntegration(seed=b"t")
        _provider(sso, pid="corp-okta")
        sso.provider("corp-saml", "saml", 2, issuer="https://idp2.io",
                     entity_id="https://idp2.io")
        d = sso.login("corp-okta", _assertion(), 3)
        with self.assertRaises(BadAssertionError):
            sso.jit("corp-saml", d, 4)

    def test_subject_lookup_unknown(self):
        sso = SSOIntegration(seed=b"t")
        with self.assertRaises(UnknownSubjectError):
            sso.subject("usr_missing")


class TestSeqAndAudit(unittest.TestCase):
    def test_seq_rewind_refused(self):
        sso = SSOIntegration(seed=b"t")
        _provider(sso, seq=5)
        with self.assertRaises(SeqOrderError):
            _provider(sso, pid="other", seq=5)

    def test_failed_mutation_consumes_seq(self):
        sso = SSOIntegration(seed=b"t")
        _provider(sso, seq=1)
        with self.assertRaises(DuplicateProviderError):
            _provider(sso, seq=2)
        # seq 2 is burnt; next legal mutation must use seq 3
        with self.assertRaises(SeqOrderError):
            _provider(sso, pid="other", seq=2)
        rec = _provider(sso, pid="other", seq=3)
        self.assertEqual(rec.provider_id, "other")

    def test_audit_shapes_and_no_secret_leak(self):
        sso = SSOIntegration(seed=b"t")
        _provider(sso)
        d = sso.login("corp-okta", _assertion(), 2)
        kinds = [e["kind"] for e in sso.audit_log()]
        self.assertIn("provider-registered", kinds)
        self.assertIn("login", kinds)
        for e in sso.audit_log():
            self.assertEqual(e["schema"], AUDIT_SCHEMA)
            blob = repr(e["payload"])
            self.assertNotIn("topsecret", blob)
            self.assertNotIn("sig1", blob)

    def test_audit_event_helper_and_bad_kind(self):
        ev = sso_integration_audit_event(1, "login", {"provider_id": "x"})
        self.assertEqual(ev["schema"], AUDIT_SCHEMA)
        self.assertEqual(ev["module"], SSO_INTEGRATION_VERSION)
        # banned keys are stripped
        ev2 = sso_integration_audit_event(2, "jit-provisioned",
                                          {"sub": "alice",
                                           "subject_id": "usr_abc"})
        self.assertNotIn("sub", ev2["payload"])
        self.assertIn("subject_id", ev2["payload"])
        with self.assertRaises(ValueError):
            sso_integration_audit_event(3, "bogus", {})

    def test_concurrency_smoke(self):
        sso = SSOIntegration(seed=b"t")
        _provider(sso)
        errors = []
        seq_lock = threading.Lock()
        state = {"seq": 2}

        def work(i):
            try:
                a = _assertion(nonce=f"th-{i}", exp_seq=10_000)
                with seq_lock:
                    state["seq"] += 1
                    sso.login("corp-okta", a, state["seq"])
                sso.providers()
                sso.audit_log()
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=work, args=(i,))
                   for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
