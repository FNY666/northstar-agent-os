"""Tests for oauth2_provider: authorization-code + PKCE grant ledger."""

import unittest

from oauth2_provider import (
    SCHEMA_PIN,
    OAUTH2_PROVIDER_VERSION,
    AuthorizationCode,
    ClientRecord,
    DuplicateClientError,
    ExpiredTokenError,
    InvalidClientError,
    InvalidGrantError,
    OAuth2Provider,
    PKCEError,
    RedirectMismatchError,
    RevocationRecord,
    ScopeError,
    TokenInfo,
    TokenReuseError,
    TokenSet,
    UnknownClientError,
    UnknownTokenError,
    _pkce_s256_challenge,
    main,
    oauth2_provider_audit_event,
)

VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"  # 43 chars
CALLBACK = "https://app.example.com/callback"


def fresh(**kwargs):
    kwargs.setdefault("session_secret", b"test-secret")
    return OAuth2Provider(**kwargs)


def reg(provider, seq=1, **kwargs):
    kwargs.setdefault("client_id", "webapp")
    kwargs.setdefault("redirect_uris", (CALLBACK,))
    return provider.register_client(seq=seq, **kwargs)


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(OAUTH2_PROVIDER_VERSION, "oauth2-provider.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.oauth2-provider.v1")
        p = fresh()
        client = reg(p)
        self.assertEqual(client.version, OAUTH2_PROVIDER_VERSION)
        self.assertEqual(client.schema, SCHEMA_PIN)
        self.assertTrue(client.digest.startswith("sha256:"))

    def test_stdlib_only(self):
        import ast
        from pathlib import Path

        tree = ast.parse(
            (Path(__file__).resolve().parent.parent / "oauth2_provider.py").read_text()
        )
        allowed = {
            "base64", "hashlib", "hmac", "threading", "dataclasses",
            "typing", "__future__", "json", "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestRegistration(unittest.TestCase):
    def test_register_confidential(self):
        p = fresh()
        client = reg(p, scope=("read", "write"))
        self.assertIsInstance(client, ClientRecord)
        self.assertEqual(client.client_type, "confidential")
        self.assertEqual(client.scope, ("read", "write"))

    def test_register_public(self):
        p = fresh()
        client = reg(p, client_id="spa", client_type="public")
        self.assertEqual(client.client_type, "public")

    def test_duplicate_client(self):
        p = fresh()
        reg(p)
        with self.assertRaises(DuplicateClientError):
            reg(p, seq=2)

    def test_bad_client_type(self):
        p = fresh()
        with self.assertRaises(ValueError):
            reg(p, seq=1, client_type="native")

    def test_redirect_fragment_refused(self):
        p = fresh()
        with self.assertRaises(ValueError):
            reg(p, seq=1, redirect_uris=(CALLBACK + "#frag",))

    def test_duplicate_redirect_uris_refused(self):
        p = fresh()
        with self.assertRaises(ValueError):
            reg(p, seq=1, redirect_uris=(CALLBACK, CALLBACK))

    def test_public_client_with_secret_refused(self):
        p = fresh()
        with self.assertRaises(ValueError):
            reg(p, seq=1, client_type="public", secret="nope")

    def test_client_view(self):
        p = fresh()
        client = reg(p)
        self.assertEqual(p.client("webapp").digest, client.digest)
        with self.assertRaises(UnknownClientError):
            p.client("ghost")

    def test_seq_must_increase(self):
        p = fresh()
        reg(p, seq=5)
        with self.assertRaises(ValueError):
            reg(p, seq=5, client_id="other")

    def test_bad_seq_type(self):
        p = fresh()
        with self.assertRaises(TypeError):
            reg(p, seq=True)


class TestAuthorize(unittest.TestCase):
    def test_authorize_happy_path(self):
        p = fresh()
        reg(p)
        grant = p.authorize("webapp", CALLBACK, "code", seq=2, scope=("read",))
        self.assertIsInstance(grant, AuthorizationCode)
        self.assertTrue(grant.code.startswith("ac_"))
        self.assertEqual(grant.expires_seq, 2 + 600)

    def test_authorize_state_echo(self):
        p = fresh()
        reg(p)
        grant = p.authorize("webapp", CALLBACK, "code", seq=2, state="csrf-123")
        self.assertEqual(grant.state, "csrf-123")

    def test_authorize_unknown_client(self):
        p = fresh()
        with self.assertRaises(UnknownClientError):
            p.authorize("ghost", CALLBACK, "code", seq=1)

    def test_authorize_redirect_exact_match(self):
        p = fresh()
        reg(p)
        # Prefix tricks must fail: exact match only.
        with self.assertRaises(RedirectMismatchError):
            p.authorize("webapp", CALLBACK + ".evil.com", "code", seq=2)
        with self.assertRaises(RedirectMismatchError):
            p.authorize("webapp", CALLBACK + "?x=1", "code", seq=3)

    def test_authorize_bad_response_type(self):
        p = fresh()
        reg(p)
        with self.assertRaises(InvalidGrantError):
            p.authorize("webapp", CALLBACK, "token", seq=2)

    def test_authorize_scope_exceeds(self):
        p = fresh()
        reg(p, scope=("read",))
        with self.assertRaises(ScopeError):
            p.authorize("webapp", CALLBACK, "code", seq=2, scope=("read", "admin"))

    def test_public_client_requires_pkce(self):
        p = fresh()
        reg(p, client_id="spa", client_type="public")
        with self.assertRaises(PKCEError):
            p.authorize("spa", CALLBACK, "code", seq=2)

    def test_bad_challenge_method(self):
        p = fresh()
        reg(p, client_id="spa", client_type="public")
        with self.assertRaises(PKCEError):
            p.authorize(
                "spa", CALLBACK, "code", seq=2,
                code_challenge="x" * 43, code_challenge_method="md5",
            )


class TestTokenExchange(unittest.TestCase):
    def _code(self, p, seq=2, **kwargs):
        reg(p)
        return p.authorize("webapp", CALLBACK, "code", seq=seq, **kwargs)

    def test_exchange_happy_path(self):
        p = fresh()
        grant = self._code(p)
        secret = p._client_secrets["webapp"]
        tokens = p.token(grant.code, "webapp", seq=3, client_secret=secret)
        self.assertIsInstance(tokens, TokenSet)
        self.assertEqual(tokens.token_type, "Bearer")
        self.assertTrue(tokens.access_token.startswith("at_"))
        self.assertTrue(tokens.refresh_token.startswith("rt_"))
        self.assertEqual(tokens.expires_in_seqs, 3600)

    def test_exchange_wrong_secret(self):
        p = fresh()
        grant = self._code(p)
        with self.assertRaises(InvalidClientError):
            p.token(grant.code, "webapp", seq=3, client_secret=b"wrong")

    def test_exchange_missing_secret(self):
        p = fresh()
        grant = self._code(p)
        with self.assertRaises(InvalidClientError):
            p.token(grant.code, "webapp", seq=3)

    def test_code_single_use(self):
        p = fresh()
        grant = self._code(p)
        secret = p._client_secrets["webapp"]
        p.token(grant.code, "webapp", seq=3, client_secret=secret)
        with self.assertRaises(InvalidGrantError):
            p.token(grant.code, "webapp", seq=4, client_secret=secret)

    def test_code_wrong_client(self):
        p = fresh()
        reg(p, seq=1)
        reg(p, seq=2, client_id="other", redirect_uris=(CALLBACK,))
        grant = p.authorize("webapp", CALLBACK, "code", seq=3)
        secret = p._client_secrets["other"]
        with self.assertRaises(InvalidGrantError):
            p.token(grant.code, "other", seq=4, client_secret=secret)

    def test_code_redirect_mismatch(self):
        p = fresh()
        grant = self._code(p)
        secret = p._client_secrets["webapp"]
        with self.assertRaises(RedirectMismatchError):
            p.token(
                grant.code, "webapp", seq=3,
                redirect_uri="https://evil.example.com/",
                client_secret=secret,
            )

    def test_code_expired(self):
        p = fresh(code_lifetime_seqs=10)
        grant = self._code(p, seq=2)
        secret = p._client_secrets["webapp"]
        with self.assertRaises(InvalidGrantError):
            p.token(grant.code, "webapp", seq=13, client_secret=secret)
        # Consumed: still dead afterwards.
        with self.assertRaises(InvalidGrantError):
            p.token(grant.code, "webapp", seq=14, client_secret=secret)

    def test_exchange_unknown_code(self):
        p = fresh()
        reg(p)
        with self.assertRaises(InvalidGrantError):
            p.token("ac_nope", "webapp", seq=2,
                    client_secret=p._client_secrets["webapp"])


class TestPKCE(unittest.TestCase):
    def _public(self, seq=1):
        p = fresh()
        reg(p, seq=seq, client_id="spa", client_type="public")
        return p

    def test_s256_happy_path(self):
        p = self._public()
        challenge = _pkce_s256_challenge(VERIFIER)
        grant = p.authorize(
            "spa", CALLBACK, "code", seq=2,
            code_challenge=challenge, code_challenge_method="S256",
        )
        tokens = p.token(grant.code, "spa", seq=3, code_verifier=VERIFIER)
        self.assertEqual(tokens.client_id, "spa")

    def test_s256_wrong_verifier(self):
        p = self._public()
        challenge = _pkce_s256_challenge(VERIFIER)
        grant = p.authorize(
            "spa", CALLBACK, "code", seq=2,
            code_challenge=challenge, code_challenge_method="S256",
        )
        bad = "e" * 43
        with self.assertRaises(PKCEError):
            p.token(grant.code, "spa", seq=3, code_verifier=bad)

    def test_plain_happy_path(self):
        p = self._public()
        grant = p.authorize(
            "spa", CALLBACK, "code", seq=2,
            code_challenge=VERIFIER, code_challenge_method="plain",
        )
        tokens = p.token(grant.code, "spa", seq=3, code_verifier=VERIFIER)
        self.assertTrue(tokens.access_token.startswith("at_"))

    def test_missing_verifier(self):
        p = self._public()
        grant = p.authorize(
            "spa", CALLBACK, "code", seq=2,
            code_challenge="x" * 43, code_challenge_method="plain",
        )
        with self.assertRaises(PKCEError):
            p.token(grant.code, "spa", seq=3)

    def test_verifier_length_bounds(self):
        p = self._public()
        grant = p.authorize(
            "spa", CALLBACK, "code", seq=2,
            code_challenge="x" * 43, code_challenge_method="plain",
        )
        with self.assertRaises(PKCEError):
            p.token(grant.code, "spa", seq=3, code_verifier="short")


class TestRefresh(unittest.TestCase):
    def _tokens(self, p, seq=2):
        reg(p)
        grant = p.authorize("webapp", CALLBACK, "code", seq=seq)
        secret = p._client_secrets["webapp"]
        return p.token(grant.code, "webapp", seq=seq + 1, client_secret=secret), secret

    def test_refresh_rotates(self):
        p = fresh()
        tokens, secret = self._tokens(p)
        rotated = p.refresh(tokens.refresh_token, "webapp", seq=4, client_secret=secret)
        self.assertNotEqual(rotated.access_token, tokens.access_token)
        self.assertNotEqual(rotated.refresh_token, tokens.refresh_token)

    def test_refresh_reuse_kills_family(self):
        p = fresh()
        tokens, secret = self._tokens(p)
        rotated = p.refresh(tokens.refresh_token, "webapp", seq=4, client_secret=secret)
        with self.assertRaises(TokenReuseError):
            p.refresh(tokens.refresh_token, "webapp", seq=5, client_secret=secret)
        # Family revoked: the rotated access token is dead too.
        with self.assertRaises(UnknownTokenError):
            p.token_info(rotated.access_token, seq=6)

    def test_refresh_unknown_token(self):
        p = fresh()
        reg(p)
        with self.assertRaises(UnknownTokenError):
            p.refresh("rt_nope", "webapp", seq=2,
                      client_secret=p._client_secrets["webapp"])

    def test_refresh_wrong_client(self):
        p = fresh()
        tokens, _ = self._tokens(p)
        reg(p, seq=4, client_id="other", redirect_uris=(CALLBACK,))
        with self.assertRaises(InvalidGrantError):
            p.refresh(tokens.refresh_token, "other", seq=5,
                      client_secret=p._client_secrets["other"])

    def test_refresh_scope_narrowing_ok(self):
        p = fresh()
        reg(p, scope=("read", "write"))
        grant = p.authorize("webapp", CALLBACK, "code", seq=2, scope=("read", "write"))
        secret = p._client_secrets["webapp"]
        tokens = p.token(grant.code, "webapp", seq=3, client_secret=secret)
        narrowed = p.refresh(
            tokens.refresh_token, "webapp", seq=4,
            client_secret=secret, scope=("read",),
        )
        self.assertEqual(narrowed.scope, ("read",))

    def test_refresh_scope_widening_refused(self):
        p = fresh()
        tokens, secret = self._tokens(p)
        with self.assertRaises(ScopeError):
            p.refresh(tokens.refresh_token, "webapp", seq=4,
                      client_secret=secret, scope=("admin",))


class TestRevokeAndInfo(unittest.TestCase):
    def test_revoke_access_token(self):
        p = fresh()
        reg(p)
        grant = p.authorize("webapp", CALLBACK, "code", seq=2)
        secret = p._client_secrets["webapp"]
        tokens = p.token(grant.code, "webapp", seq=3, client_secret=secret)
        record = p.revoke(tokens.access_token, seq=4)
        self.assertIsInstance(record, RevocationRecord)
        self.assertEqual(record.kind, "access")
        with self.assertRaises(UnknownTokenError):
            p.token_info(tokens.access_token, seq=5)

    def test_revoke_refresh_token(self):
        p = fresh()
        reg(p)
        grant = p.authorize("webapp", CALLBACK, "code", seq=2)
        secret = p._client_secrets["webapp"]
        tokens = p.token(grant.code, "webapp", seq=3, client_secret=secret)
        record = p.revoke(tokens.refresh_token, seq=4)
        self.assertEqual(record.kind, "refresh")
        with self.assertRaises(UnknownTokenError):
            p.refresh(tokens.refresh_token, "webapp", seq=5, client_secret=secret)

    def test_revoke_unknown(self):
        p = fresh()
        with self.assertRaises(UnknownTokenError):
            p.revoke("at_nope", seq=1)

    def test_token_info_expired(self):
        p = fresh(access_token_lifetime_seqs=10)
        reg(p)
        grant = p.authorize("webapp", CALLBACK, "code", seq=2)
        secret = p._client_secrets["webapp"]
        tokens = p.token(grant.code, "webapp", seq=3, client_secret=secret)
        info = p.token_info(tokens.access_token, seq=14)
        self.assertIsInstance(info, TokenInfo)
        self.assertFalse(info.active)

    def test_token_info_unknown(self):
        p = fresh()
        with self.assertRaises(UnknownTokenError):
            p.token_info("at_nope", seq=1)

    def test_frozen_records(self):
        p = fresh()
        client = reg(p)
        with self.assertRaises(Exception):
            client.client_id = "mutant"  # frozen dataclass


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        p = fresh()
        client = reg(p)
        grant = p.authorize("webapp", CALLBACK, "code", seq=2)
        secret = p._client_secrets["webapp"]
        tokens = p.token(grant.code, "webapp", seq=3, client_secret=secret)
        revocation = p.revoke(tokens.access_token, seq=4)
        event = oauth2_provider_audit_event("client-registered", 10, client=client)
        self.assertEqual(event["event"], "oauth2-provider-client-registered")
        self.assertEqual(event["schema"], SCHEMA_PIN)
        event = oauth2_provider_audit_event("code-issued", 11, code=grant)
        self.assertIn("code_digest", event)
        event = oauth2_provider_audit_event("token-issued", 12, tokens=tokens)
        self.assertIn("token_digest", event)
        event = oauth2_provider_audit_event("token-revoked", 13, revocation=revocation)
        self.assertEqual(event["kind"], "access")
        event = oauth2_provider_audit_event("rejected", 14)
        self.assertEqual(event["audit_seq"], 14)
        # Secrets and token values never leak through audit.
        blob = str(event)
        self.assertNotIn("test-secret", blob)

    def test_audit_bad_kind(self):
        with self.assertRaises(ValueError):
            oauth2_provider_audit_event("nope", 1)

    def test_audit_bad_seq(self):
        with self.assertRaises(TypeError):
            oauth2_provider_audit_event("rejected", True)


class TestMain(unittest.TestCase):
    def test_main(self):
        main()  # raises on failure


if __name__ == "__main__":
    unittest.main()
