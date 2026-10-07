"""Tests for oidc_provider: simulated OpenID Connect identity bookkeeping."""

import ast
import unittest
from pathlib import Path

from oidc_provider import (
    OIDCProvider,
    OIDCError,
    DuplicateClientError,
    UnknownClientError,
    UnknownCodeError,
    CodeReuseError,
    UnknownTokenError,
    RevokedTokenError,
    ExpiredTokenError,
    OIDC_PROVIDER_VERSION,
    SCHEMA_PIN,
    DEFAULT_TOKEN_LIFETIME_SEQS,
    oidc_provider_audit_event,
)


def make_provider():
    return OIDCProvider("https://idp.example.com", b"0" * 32)


def registered(p, seq=1, client_id="web", scopes=("openid", "profile", "email")):
    return p.register_client(
        client_id, ["https://app.example.com/cb"], list(scopes), seq
    )


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(OIDC_PROVIDER_VERSION, "oidc-provider.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.oidc-provider.v1")

    def test_bad_issuer_rejected(self):
        with self.assertRaises(OIDCError):
            OIDCProvider("", b"0" * 32)
        with self.assertRaises(OIDCError):
            OIDCProvider(123, b"0" * 32)

    def test_bad_secret_rejected(self):
        with self.assertRaises(OIDCError):
            OIDCProvider("https://idp.example.com", b"short")
        with self.assertRaises(OIDCError):
            OIDCProvider("https://idp.example.com", "not-bytes" * 4)


class TestDiscovery(unittest.TestCase):
    def test_discover_shape(self):
        doc = make_provider().discover()
        self.assertEqual(doc.issuer, "https://idp.example.com")
        self.assertEqual(
            doc.authorization_endpoint, "https://idp.example.com/authorize"
        )
        self.assertEqual(doc.token_endpoint, "https://idp.example.com/token")
        self.assertEqual(doc.userinfo_endpoint, "https://idp.example.com/userinfo")
        self.assertIn("openid", doc.scopes_supported)
        self.assertIn("code", doc.response_types_supported)
        self.assertTrue(doc.digest.startswith("sha256:"))
        self.assertEqual(doc.version, OIDC_PROVIDER_VERSION)

    def test_discover_deterministic(self):
        a = make_provider().discover()
        b = make_provider().discover()
        self.assertEqual(a.digest, b.digest)

    def test_discover_as_dict(self):
        d = make_provider().discover().as_dict()
        self.assertEqual(d["issuer"], "https://idp.example.com")
        self.assertEqual(d["schema"], SCHEMA_PIN)


class TestClients(unittest.TestCase):
    def test_register_roundtrip(self):
        p = make_provider()
        rec = registered(p)
        self.assertEqual(rec.client_id, "web")
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(rec.seq, 1)
        self.assertIn("web", p.clients())

    def test_duplicate_client_refused(self):
        p = make_provider()
        registered(p)
        with self.assertRaises(DuplicateClientError):
            registered(p, seq=2)

    def test_http_redirect_uri_refused(self):
        p = make_provider()
        with self.assertRaises(OIDCError):
            p.register_client(
                "web", ["http://evil.example.com/cb"], ["openid"], 1
            )

    def test_localhost_redirect_uri_allowed(self):
        p = make_provider()
        rec = p.register_client(
            "native", ["http://localhost:8080/cb"], ["openid"], 1
        )
        self.assertEqual(rec.redirect_uris, ("http://localhost:8080/cb",))

    def test_unsupported_scope_refused(self):
        p = make_provider()
        with self.assertRaises(OIDCError):
            p.register_client("web", ["https://a.example/cb"], ["openid", "nope"], 1)

    def test_missing_openid_scope_refused(self):
        p = make_provider()
        with self.assertRaises(OIDCError):
            p.register_client("web", ["https://a.example/cb"], ["profile"], 1)

    def test_seq_rewind_refused(self):
        p = make_provider()
        registered(p, seq=5)
        with self.assertRaises(OIDCError):
            registered(p, seq=5, client_id="web2")
        with self.assertRaises(OIDCError):
            registered(p, seq=4, client_id="web3")


class TestProfiles(unittest.TestCase):
    def test_set_profile_roundtrip(self):
        p = make_provider()
        registered(p)
        p.set_profile("alice", {"name": "Alice", "email": "a@example.com"}, 2)
        code = p.authorize("web", "alice", ["openid", "profile", "email"], 3)
        tokens = p.id_token(code.code, 4, now_seq=10)
        info = p.userinfo(tokens.access_token.token_id, 5, now_seq=10)
        self.assertEqual(info.claims["name"], "Alice")
        self.assertEqual(info.claims["email"], "a@example.com")
        self.assertFalse(info.claims["email_verified"])
        self.assertEqual(info.sub, "alice")

    def test_profile_bad_value_refused(self):
        p = make_provider()
        with self.assertRaises(OIDCError):
            p.set_profile("alice", {"name": 123}, 1)

    def test_profile_unknown_claim_ignored(self):
        p = make_provider()
        registered(p)
        p.set_profile("alice", {"name": "Alice", "weird": "x"}, 2)
        code = p.authorize("web", "alice", ["openid"], 3)
        tokens = p.id_token(code.code, 4, now_seq=10)
        info = p.userinfo(tokens.access_token.token_id, 5, now_seq=10)
        self.assertNotIn("weird", info.claims)


class TestAuthCodeFlow(unittest.TestCase):
    def test_authorize_roundtrip(self):
        p = make_provider()
        registered(p)
        code = p.authorize("web", "alice", ["openid", "profile"], 2, nonce="n-1")
        self.assertTrue(code.code.startswith("code-"))
        self.assertEqual(code.nonce, "n-1")
        self.assertTrue(code.digest.startswith("sha256:"))

    def test_authorize_unknown_client(self):
        p = make_provider()
        with self.assertRaises(UnknownClientError):
            p.authorize("ghost", "alice", ["openid"], 1)

    def test_authorize_scope_not_granted(self):
        p = make_provider()
        registered(p, scopes=("openid",))
        with self.assertRaises(OIDCError):
            p.authorize("web", "alice", ["openid", "email"], 2)

    def test_authorize_unregistered_redirect_uri(self):
        p = make_provider()
        p.register_client(
            "web",
            ["https://a.example/cb", "https://b.example/cb"],
            ["openid"],
            1,
        )
        with self.assertRaises(OIDCError):
            p.authorize(
                "web", "alice", ["openid"], 2,
                redirect_uri="https://evil.example/cb",
            )

    def test_id_token_issuance(self):
        p = make_provider()
        registered(p)
        code = p.authorize("web", "alice", ["openid"], 2)
        tokens = p.id_token(code.code, 3, now_seq=10)
        parts = tokens.id_token.token.split(".")
        self.assertEqual(len(parts), 3)  # real JWT shape
        self.assertEqual(tokens.id_token.claims["iss"], "https://idp.example.com")
        self.assertEqual(tokens.id_token.claims["sub"], "alice")
        self.assertEqual(tokens.id_token.claims["aud"], "web")
        self.assertEqual(tokens.id_token.claims["exp"], 10 + DEFAULT_TOKEN_LIFETIME_SEQS)
        self.assertIsNone(tokens.refresh_token)  # no offline_access

    def test_code_single_use(self):
        p = make_provider()
        registered(p)
        code = p.authorize("web", "alice", ["openid"], 2)
        p.id_token(code.code, 3, now_seq=10)
        with self.assertRaises(CodeReuseError):
            p.id_token(code.code, 4, now_seq=10)

    def test_unknown_code_refused(self):
        p = make_provider()
        with self.assertRaises(UnknownCodeError):
            p.id_token("code-999", 1, now_seq=10)

    def test_offline_access_gets_refresh_token(self):
        p = make_provider()
        registered(p, scopes=("openid", "offline_access"))
        code = p.authorize("web", "alice", ["openid", "offline_access"], 2)
        tokens = p.id_token(code.code, 3, now_seq=10)
        self.assertIsNotNone(tokens.refresh_token)
        self.assertTrue(tokens.refresh_token.token_id.startswith("rt-"))


class TestVerify(unittest.TestCase):
    def test_verify_happy_path(self):
        p = make_provider()
        registered(p)
        code = p.authorize("web", "alice", ["openid"], 2, nonce="n-9")
        tokens = p.id_token(code.code, 3, now_seq=10)
        rep = p.verify_id_token(tokens.id_token.token, "web", now_seq=11, seq=4)
        self.assertTrue(rep.valid)
        self.assertEqual(rep.reason, "ok")
        self.assertEqual(rep.claims["sub"], "alice")
        self.assertEqual(rep.claims["nonce"], "n-9")

    def test_verify_bad_signature(self):
        p = make_provider()
        registered(p)
        code = p.authorize("web", "alice", ["openid"], 2)
        tokens = p.id_token(code.code, 3, now_seq=10)
        tampered = tokens.id_token.token[:-2] + "AA"
        rep = p.verify_id_token(tampered, "web", now_seq=11, seq=4)
        self.assertFalse(rep.valid)
        self.assertEqual(rep.reason, "bad-signature")

    def test_verify_wrong_audience(self):
        p = make_provider()
        registered(p)
        code = p.authorize("web", "alice", ["openid"], 2)
        tokens = p.id_token(code.code, 3, now_seq=10)
        rep = p.verify_id_token(tokens.id_token.token, "other", now_seq=11, seq=4)
        self.assertFalse(rep.valid)
        self.assertEqual(rep.reason, "audience-mismatch")

    def test_verify_expired(self):
        p = make_provider()
        registered(p)
        code = p.authorize("web", "alice", ["openid"], 2)
        tokens = p.id_token(code.code, 3, now_seq=10)
        rep = p.verify_id_token(
            tokens.id_token.token, "web", now_seq=10 + DEFAULT_TOKEN_LIFETIME_SEQS, seq=4
        )
        self.assertFalse(rep.valid)
        self.assertEqual(rep.reason, "expired")

    def test_verify_malformed_returns_invalid(self):
        p = make_provider()
        for bad in ("not-a-token", "a.b", 123, ""):
            rep = p.verify_id_token(bad, "web", now_seq=1, seq=1)
            self.assertFalse(rep.valid)

    def test_verify_wrong_issuer_key_fails(self):
        p1 = make_provider()
        p2 = OIDCProvider("https://idp.example.com", b"1" * 32)
        registered(p1)
        registered(p2)
        code = p1.authorize("web", "alice", ["openid"], 2)
        tokens = p1.id_token(code.code, 3, now_seq=10)
        rep = p2.verify_id_token(tokens.id_token.token, "web", now_seq=11, seq=4)
        self.assertFalse(rep.valid)


class TestUserinfo(unittest.TestCase):
    def test_unknown_token_refused(self):
        p = make_provider()
        with self.assertRaises(UnknownTokenError):
            p.userinfo("at-999", 1, now_seq=1)

    def test_expired_access_token_refused(self):
        p = make_provider()
        registered(p)
        code = p.authorize("web", "alice", ["openid"], 2)
        tokens = p.id_token(code.code, 3, now_seq=10)
        with self.assertRaises(ExpiredTokenError):
            p.userinfo(
                tokens.access_token.token_id, 4,
                now_seq=10 + DEFAULT_TOKEN_LIFETIME_SEQS,
            )


class TestRefreshRevoke(unittest.TestCase):
    def test_refresh_rotation(self):
        p = make_provider()
        registered(p, scopes=("openid", "offline_access"))
        code = p.authorize("web", "alice", ["openid", "offline_access"], 2)
        t1 = p.id_token(code.code, 3, now_seq=10)
        rt = t1.refresh_token.token_id
        t2 = p.exchange_refresh(rt, 4, now_seq=11)
        self.assertNotEqual(t2.access_token.token_id, t1.access_token.token_id)
        self.assertTrue(p.is_revoked(rt))
        with self.assertRaises(RevokedTokenError):
            p.exchange_refresh(rt, 5, now_seq=12)

    def test_revoke_access_token(self):
        p = make_provider()
        registered(p)
        code = p.authorize("web", "alice", ["openid"], 2)
        tokens = p.id_token(code.code, 3, now_seq=10)
        at = tokens.access_token.token_id
        rec = p.revoke(at, 4)
        self.assertEqual(rec.token_type, "access_token")
        self.assertTrue(p.is_revoked(at))
        with self.assertRaises(RevokedTokenError):
            p.userinfo(at, 5, now_seq=11)

    def test_revoke_unknown_refused(self):
        p = make_provider()
        with self.assertRaises(UnknownTokenError):
            p.revoke("at-999", 1)

    def test_revoke_twice_refused(self):
        p = make_provider()
        registered(p)
        code = p.authorize("web", "alice", ["openid"], 2)
        tokens = p.id_token(code.code, 3, now_seq=10)
        p.revoke(tokens.access_token.token_id, 4)
        with self.assertRaises(RevokedTokenError):
            p.revoke(tokens.access_token.token_id, 5)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        ev = oidc_provider_audit_event(
            "client-registered", 1, {"client_id": "web"}
        )
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["kind"], "oidc-provider.client-registered")
        self.assertEqual(ev["seq"], 1)

    def test_audit_unknown_kind_rejected(self):
        with self.assertRaises(OIDCError):
            oidc_provider_audit_event("nope", 1)

    def test_audit_secret_banned(self):
        with self.assertRaises(OIDCError):
            oidc_provider_audit_event("tokens-issued", 1, {"token": "abc"})

    def test_audit_bad_seq_rejected(self):
        with self.assertRaises(OIDCError):
            oidc_provider_audit_event("authorized", -1)


class TestHouseStyle(unittest.TestCase):
    def test_stdlib_only(self):
        src = Path(__file__).resolve().parent.parent / "oidc_provider.py"
        tree = ast.parse(src.read_text())
        allowed = {
            "base64", "hashlib", "hmac", "threading", "dataclasses",
            "typing", "__future__", "canonical_json", "json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)

    def test_frozen_records(self):
        import dataclasses

        from oidc_provider import DiscoveryDocument, ClientRecord, AuthCode

        for cls in (DiscoveryDocument, ClientRecord, AuthCode):
            with self.assertRaises(dataclasses.FrozenInstanceError):
                inst = cls.__new__(cls)
                inst.seq = 1  # type: ignore[attr-defined]

    def test_main(self):
        from oidc_provider import main

        main()


if __name__ == "__main__":
    unittest.main()
