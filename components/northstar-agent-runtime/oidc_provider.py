"""OIDC provider: OpenID Connect identity bookkeeping (simulated).

Research note: OpenID Connect 1.0 (the identity layer on OAuth 2.0) is the
industry-standard SSO protocol — the shape behind "Sign in with Google",
Auth0, Keycloak, and enterprise IdPs. The load-bearing security properties
are well studied (RFC 6749, OpenID Connect Core 1.0, FAPI 2.0, RFC 9700
OAuth security BCP):

* **Discovery** — ``discover()`` returns the OpenID Provider Metadata
  document (RFC 8414-style): issuer, authorization/token/userinfo/JWKS
  endpoints, supported scopes, response types, and claims. Clients pin
  the issuer and fetch metadata from the well-known URI; here the
  document is digest-pinned so drift is observable.
* **Client registration** — ``register_client()`` pins a client_id to its
  redirect URIs and allowed scopes. Redirect-URI validation is the
  primary defense against authorization-code interception attacks
  (fail-closed: https only, ``http://localhost`` the sole exception).
* **Authorization code flow** — ``authorize()`` mints a single-use code
  bound to (client, user, scopes, nonce). ``id_token()`` consumes the
  code exactly once and returns a signed JWT ID Token plus an opaque
  access token. Code reuse is refused (``CodeReuseError``) — the replay
  defense.
* **ID Token** — a real JWT-shaped token (``header.payload.signature``,
  base64url) with the standard claims: ``iss``, ``sub``, ``aud``,
  ``exp``, ``iat``, ``nonce``, ``auth_time``, ``acr``. The signature is
  HMAC-SHA256 under a provider keyed secret.
* **Verification** — ``verify_id_token()`` checks signature (constant
  time), issuer, audience, and expiry, and reports a frozen
  ``VerificationReport`` instead of raising on untrusted input — a
  verifier consuming attacker-controlled tokens must not raise, it
  must *decide*.
* **UserInfo** — ``userinfo()`` returns the standard claims for a live
  access token (``sub``, ``name``, ``email``, ``email_verified``, ...).
* **Refresh** — clients granted ``offline_access`` receive a rotating
  refresh token; ``exchange_refresh()`` mints fresh tokens and burns the
  old one (rotation, reuse refused).
* **Revocation** — ``revoke()`` burns access/refresh tokens; verification
  and userinfo fail closed on revoked tokens.

Expiry is expressed in caller-supplied integer *seqs* (no wall-clock):
tokens carry ``exp_seq`` and every verifier takes ``now_seq``. A host
that lies about ``now_seq`` gets a consistent-but-fictional answer —
the same GIGO boundary as every other bookkeeping module.

Honest scope: this is the *decision and bookkeeping layer* of an IdP,
not a confidentiality or identity boundary. The HMAC signature stands in
for RS256 (a real deployment signs with an asymmetric key published at
``jwks_uri``); it proves "the holder of the provider secret minted this",
never "the user is who they claim". It cannot observe the browser, the
network, or the user's consent; ``authorize()`` books that the host
*reported* consent. Pair with ``remote_attestation`` for real endpoint
identity and ``mcp_approval_combo`` for human consent gates.

Version pin: oidc-provider.v1
Schema pin: northstar.oidc-provider.v1
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
OIDC_PROVIDER_VERSION = "oidc-provider.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.oidc-provider.v1"

#: Error taxonomy anchor.
ERROR_PREFIX = "oidc-provider."

#: Scopes this provider recognizes (fail-closed: unknown scopes refused).
SUPPORTED_SCOPES = frozenset(
    {"openid", "profile", "email", "address", "phone", "offline_access"}
)

#: Standard userinfo claims this provider will release.
USERINFO_CLAIMS = ("sub", "name", "given_name", "family_name", "email", "email_verified")

#: Default token lifetime in caller seqs (a policy default, not a time value).
DEFAULT_TOKEN_LIFETIME_SEQS = 100

_AUDIT_KINDS = frozenset(
    {
        "client-registered",
        "authorized",
        "tokens-issued",
        "tokens-refreshed",
        "token-revoked",
        "userinfo-released",
        "rejected",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class OIDCError(Exception):
    """Base error for the OIDC provider (fail-closed taxonomy)."""


class DuplicateClientError(OIDCError):
    pass


class UnknownClientError(OIDCError):
    pass


class UnknownCodeError(OIDCError):
    pass


class CodeReuseError(OIDCError):
    pass


class UnknownTokenError(OIDCError):
    pass


class RevokedTokenError(OIDCError):
    pass


class InvalidTokenError(OIDCError):
    pass


class ExpiredTokenError(OIDCError):
    pass


class AudienceMismatchError(OIDCError):
    pass


class IssuerMismatchError(OIDCError):
    pass


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _check_seq(seq: Any, name: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise OIDCError(f"{ERROR_PREFIX}bad-{name}: {seq!r}")
    return seq


def _check_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise OIDCError(f"{ERROR_PREFIX}bad-{name}: {value!r}")
    return value


def _check_seq_monotonic(last: int, seq: int, what: str) -> None:
    if seq <= last:
        raise OIDCError(f"{ERROR_PREFIX}seq-rewind: {what} last={last} seq={seq}")


def _sha256_pin(*parts: bytes) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(len(p).to_bytes(8, "big"))
        h.update(p)
    return "sha256:" + h.hexdigest()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _check_redirect_uri(uri: Any) -> str:
    uri = _check_str(uri, "redirect-uri")
    low = uri.lower()
    if low.startswith("https://"):
        return uri
    if low.startswith("http://localhost") or low.startswith("http://127.0.0.1"):
        return uri
    raise OIDCError(f"{ERROR_PREFIX}redirect-uri-not-https: {uri!r}")


def _check_scopes(scopes: Any) -> Tuple[str, ...]:
    if isinstance(scopes, str) or not isinstance(scopes, (tuple, list, frozenset)):
        raise OIDCError(f"{ERROR_PREFIX}bad-scopes: {scopes!r}")
    out = tuple(sorted(set(scopes)))
    for s in out:
        if not isinstance(s, str) or s not in SUPPORTED_SCOPES:
            raise OIDCError(f"{ERROR_PREFIX}unsupported-scope: {s!r}")
    if "openid" not in out:
        raise OIDCError(f"{ERROR_PREFIX}missing-openid-scope")
    return out


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DiscoveryDocument:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str
    scopes_supported: Tuple[str, ...]
    response_types_supported: Tuple[str, ...]
    claims_supported: Tuple[str, ...]
    id_token_signing_alg_values_supported: Tuple[str, ...]
    digest: str
    version: str = OIDC_PROVIDER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "issuer": self.issuer,
            "authorization_endpoint": self.authorization_endpoint,
            "token_endpoint": self.token_endpoint,
            "userinfo_endpoint": self.userinfo_endpoint,
            "jwks_uri": self.jwks_uri,
            "scopes_supported": list(self.scopes_supported),
            "response_types_supported": list(self.response_types_supported),
            "claims_supported": list(self.claims_supported),
            "id_token_signing_alg_values_supported": list(
                self.id_token_signing_alg_values_supported
            ),
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class ClientRecord:
    client_id: str
    redirect_uris: Tuple[str, ...]
    scopes: Tuple[str, ...]
    digest: str
    seq: int
    version: str = OIDC_PROVIDER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "client_id": self.client_id,
            "redirect_uris": list(self.redirect_uris),
            "scopes": list(self.scopes),
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class AuthCode:
    code: str
    client_id: str
    user_id: str
    scopes: Tuple[str, ...]
    nonce: Optional[str]
    redirect_uri: str
    digest: str
    seq: int
    version: str = OIDC_PROVIDER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "client_id": self.client_id,
            "user_id": self.user_id,
            "scopes": list(self.scopes),
            "nonce": self.nonce,
            "redirect_uri": self.redirect_uri,
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class IDToken:
    token: str  # the JWT string
    claims: Mapping[str, Any]
    digest: str
    seq: int
    version: str = OIDC_PROVIDER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "token": self.token,
            "claims": dict(self.claims),
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class AccessTokenRecord:
    token_id: str
    client_id: str
    user_id: str
    scopes: Tuple[str, ...]
    exp_seq: int
    digest: str
    seq: int
    version: str = OIDC_PROVIDER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "token_id": self.token_id,
            "client_id": self.client_id,
            "user_id": self.user_id,
            "scopes": list(self.scopes),
            "exp_seq": self.exp_seq,
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class RefreshTokenRecord:
    token_id: str
    client_id: str
    user_id: str
    scopes: Tuple[str, ...]
    digest: str
    seq: int
    version: str = OIDC_PROVIDER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "token_id": self.token_id,
            "client_id": self.client_id,
            "user_id": self.user_id,
            "scopes": list(self.scopes),
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class TokenSet:
    id_token: IDToken
    access_token: AccessTokenRecord
    refresh_token: Optional[RefreshTokenRecord]
    digest: str
    seq: int
    version: str = OIDC_PROVIDER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "id_token": self.id_token.as_dict(),
            "access_token": self.access_token.as_dict(),
            "refresh_token": self.refresh_token.as_dict()
            if self.refresh_token
            else None,
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class VerificationReport:
    valid: bool
    reason: str
    claims: Optional[Mapping[str, Any]]
    seq: int
    version: str = OIDC_PROVIDER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "reason": self.reason,
            "claims": dict(self.claims) if self.claims is not None else None,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class UserInfo:
    sub: str
    claims: Mapping[str, Any]
    digest: str
    seq: int
    version: str = OIDC_PROVIDER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "sub": self.sub,
            "claims": dict(self.claims),
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class RevocationRecord:
    token_id: str
    token_type: str
    digest: str
    seq: int
    version: str = OIDC_PROVIDER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "token_id": self.token_id,
            "token_type": self.token_type,
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------


class OIDCProvider:
    """Simulated OpenID Connect provider: discovery, codes, tokens, userinfo.

    All time is caller-supplied seqs; all crypto is HMAC under the
    provider ``signing_secret`` (bytes). The secret never leaves the
    instance — audit events carry digests, never secrets or raw tokens.
    """

    def __init__(self, issuer: str, signing_secret: bytes) -> None:
        self._issuer = _check_str(issuer, "issuer")
        if not isinstance(signing_secret, bytes) or len(signing_secret) < 16:
            raise OIDCError(f"{ERROR_PREFIX}bad-signing-secret")
        self._secret = signing_secret
        self._lock = threading.RLock()
        self._clients: Dict[str, ClientRecord] = {}
        self._codes: Dict[str, AuthCode] = {}
        self._used_codes: set = set()
        self._access: Dict[str, AccessTokenRecord] = {}
        self._refresh: Dict[str, RefreshTokenRecord] = {}
        self._revoked: Dict[str, RevocationRecord] = {}
        self._profiles: Dict[str, Dict[str, Any]] = {}
        self._seq = 0
        self._next_id = 0

    # -- internals ------------------------------------------------------

    def _bump_seq(self, seq: int) -> None:
        _check_seq_monotonic(self._seq, seq, "provider")
        self._seq = seq

    def _mint(self, prefix: str) -> str:
        self._next_id += 1
        return f"{prefix}-{self._next_id}"

    def _sign(self, signing_input: bytes) -> bytes:
        return hmac.new(self._secret, signing_input, hashlib.sha256).digest()

    def _mint_jwt(self, claims: Dict[str, Any]) -> str:
        header = {"alg": "HS256", "typ": "JWT", "kid": "sim-key-1"}
        h = _b64url(jcs_canonical_json(header))
        p = _b64url(jcs_canonical_json(claims))
        signing_input = f"{h}.{p}".encode("ascii")
        return f"{h}.{p}." + _b64url(self._sign(signing_input))

    # -- discovery -------------------------------------------------------

    def discover(self) -> DiscoveryDocument:
        """Return the digest-pinned provider metadata document."""
        iss = self._issuer.rstrip("/")
        doc_body = {
            "issuer": iss,
            "authorization_endpoint": iss + "/authorize",
            "token_endpoint": iss + "/token",
            "userinfo_endpoint": iss + "/userinfo",
            "jwks_uri": iss + "/.well-known/jwks.json",
            "scopes_supported": sorted(SUPPORTED_SCOPES),
            "response_types_supported": ["code"],
            "claims_supported": list(USERINFO_CLAIMS)
            + ["iss", "sub", "aud", "exp", "iat", "nonce", "auth_time", "acr"],
            "id_token_signing_alg_values_supported": ["HS256"],
        }
        digest = _sha256_pin(jcs_canonical_json(doc_body))
        return DiscoveryDocument(
            issuer=doc_body["issuer"],
            authorization_endpoint=doc_body["authorization_endpoint"],
            token_endpoint=doc_body["token_endpoint"],
            userinfo_endpoint=doc_body["userinfo_endpoint"],
            jwks_uri=doc_body["jwks_uri"],
            scopes_supported=tuple(doc_body["scopes_supported"]),
            response_types_supported=tuple(doc_body["response_types_supported"]),
            claims_supported=tuple(doc_body["claims_supported"]),
            id_token_signing_alg_values_supported=tuple(
                doc_body["id_token_signing_alg_values_supported"]
            ),
            digest=digest,
        )

    # -- client management ------------------------------------------------

    def register_client(
        self,
        client_id: str,
        redirect_uris: Any,
        scopes: Any,
        seq: int,
    ) -> ClientRecord:
        """Register an OAuth client (fail-closed on dupes / bad URIs)."""
        with self._lock:
            seq = _check_seq(seq)
            self._bump_seq(seq)
            client_id = _check_str(client_id, "client-id")
            if client_id in self._clients:
                raise DuplicateClientError(
                    f"{ERROR_PREFIX}duplicate-client: {client_id!r}"
                )
            if not isinstance(redirect_uris, (tuple, list)) or not redirect_uris:
                raise OIDCError(f"{ERROR_PREFIX}bad-redirect-uris")
            uris = tuple(_check_redirect_uri(u) for u in redirect_uris)
            scopes_t = _check_scopes(scopes)
            digest = _sha256_pin(
                jcs_canonical_json(
                    {
                        "client_id": client_id,
                        "redirect_uris": sorted(uris),
                        "scopes": list(scopes_t),
                    }
                )
            )
            rec = ClientRecord(
                client_id=client_id,
                redirect_uris=uris,
                scopes=scopes_t,
                digest=digest,
                seq=seq,
            )
            self._clients[client_id] = rec
            return rec

    def set_profile(self, user_id: str, claims: Mapping[str, Any], seq: int) -> None:
        """Host-reported user profile (name/email/etc.) for userinfo."""
        with self._lock:
            seq = _check_seq(seq)
            self._bump_seq(seq)
            user_id = _check_str(user_id, "user-id")
            if not isinstance(claims, Mapping):
                raise OIDCError(f"{ERROR_PREFIX}bad-profile")
            clean: Dict[str, Any] = {}
            for k, v in claims.items():
                if k not in USERINFO_CLAIMS or k == "sub":
                    continue
                if not isinstance(v, (str, bool)):
                    raise OIDCError(f"{ERROR_PREFIX}bad-profile-value: {k!r}")
                clean[k] = v
            self._profiles[user_id] = clean

    # -- authorization code flow ------------------------------------------

    def authorize(
        self,
        client_id: str,
        user_id: str,
        scopes: Any,
        seq: int,
        redirect_uri: Optional[str] = None,
        nonce: Optional[str] = None,
    ) -> AuthCode:
        """Mint a single-use authorization code (host reports user consent)."""
        with self._lock:
            seq = _check_seq(seq)
            self._bump_seq(seq)
            client_id = _check_str(client_id, "client-id")
            user_id = _check_str(user_id, "user-id")
            client = self._clients.get(client_id)
            if client is None:
                raise UnknownClientError(f"{ERROR_PREFIX}unknown-client: {client_id!r}")
            scopes_t = _check_scopes(scopes)
            unknown = set(scopes_t) - set(client.scopes)
            if unknown:
                raise OIDCError(
                    f"{ERROR_PREFIX}scope-not-granted: {sorted(unknown)!r}"
                )
            if redirect_uri is None:
                if len(client.redirect_uris) != 1:
                    raise OIDCError(f"{ERROR_PREFIX}redirect-uri-ambiguous")
                redirect_uri = client.redirect_uris[0]
            redirect_uri = _check_redirect_uri(redirect_uri)
            if redirect_uri not in client.redirect_uris:
                raise OIDCError(f"{ERROR_PREFIX}redirect-uri-unregistered")
            if nonce is not None and (
                not isinstance(nonce, str) or not nonce or len(nonce) > 256
            ):
                raise OIDCError(f"{ERROR_PREFIX}bad-nonce")
            code = self._mint("code")
            digest = _sha256_pin(
                jcs_canonical_json(
                    {
                        "code": code,
                        "client_id": client_id,
                        "user_id": user_id,
                        "scopes": list(scopes_t),
                        "nonce": nonce,
                        "redirect_uri": redirect_uri,
                    }
                )
            )
            rec = AuthCode(
                code=code,
                client_id=client_id,
                user_id=user_id,
                scopes=scopes_t,
                nonce=nonce,
                redirect_uri=redirect_uri,
                digest=digest,
                seq=seq,
            )
            self._codes[code] = rec
            return rec

    def id_token(
        self,
        code: str,
        seq: int,
        now_seq: int,
        lifetime_seqs: int = DEFAULT_TOKEN_LIFETIME_SEQS,
    ) -> TokenSet:
        """Consume an auth code once; mint ID token + access (+refresh)."""
        with self._lock:
            seq = _check_seq(seq)
            self._bump_seq(seq)
            now_seq = _check_seq(now_seq, "now_seq")
            code = _check_str(code, "code")
            if not isinstance(lifetime_seqs, int) or isinstance(lifetime_seqs, bool) or lifetime_seqs <= 0:
                raise OIDCError(f"{ERROR_PREFIX}bad-lifetime")
            rec = self._codes.get(code)
            if rec is None:
                raise UnknownCodeError(f"{ERROR_PREFIX}unknown-code")
            if code in self._used_codes:
                raise CodeReuseError(f"{ERROR_PREFIX}code-reused")
            self._used_codes.add(code)

            exp_seq = now_seq + lifetime_seqs
            claims: Dict[str, Any] = {
                "iss": self._issuer.rstrip("/"),
                "sub": rec.user_id,
                "aud": rec.client_id,
                "exp": exp_seq,
                "iat": now_seq,
                "auth_time": rec.seq,
                "acr": "0",
                "scope": " ".join(rec.scopes),
            }
            if rec.nonce is not None:
                claims["nonce"] = rec.nonce
            jwt = self._mint_jwt(claims)
            id_digest = _sha256_pin(jcs_canonical_json(claims))
            id_token = IDToken(token=jwt, claims=dict(claims), digest=id_digest, seq=seq)

            at_id = self._mint("at")
            at_digest = _sha256_pin(
                jcs_canonical_json(
                    {
                        "token_id": at_id,
                        "client_id": rec.client_id,
                        "user_id": rec.user_id,
                        "scopes": list(rec.scopes),
                        "exp_seq": exp_seq,
                    }
                )
            )
            access = AccessTokenRecord(
                token_id=at_id,
                client_id=rec.client_id,
                user_id=rec.user_id,
                scopes=rec.scopes,
                exp_seq=exp_seq,
                digest=at_digest,
                seq=seq,
            )
            self._access[at_id] = access

            refresh: Optional[RefreshTokenRecord] = None
            if "offline_access" in rec.scopes:
                rt_id = self._mint("rt")
                rt_digest = _sha256_pin(
                    jcs_canonical_json(
                        {
                            "token_id": rt_id,
                            "client_id": rec.client_id,
                            "user_id": rec.user_id,
                            "scopes": list(rec.scopes),
                        }
                    )
                )
                refresh = RefreshTokenRecord(
                    token_id=rt_id,
                    client_id=rec.client_id,
                    user_id=rec.user_id,
                    scopes=rec.scopes,
                    digest=rt_digest,
                    seq=seq,
                )
                self._refresh[rt_id] = refresh

            digest = _sha256_pin(
                jcs_canonical_json(
                    {
                        "id_token": id_digest,
                        "access": at_digest,
                        "refresh": refresh.digest if refresh else None,
                    }
                )
            )
            return TokenSet(
                id_token=id_token,
                access_token=access,
                refresh_token=refresh,
                digest=digest,
                seq=seq,
            )

    # -- verification ------------------------------------------------------

    def verify_id_token(
        self, token: str, audience: str, now_seq: int, seq: int
    ) -> VerificationReport:
        """Verify a JWT ID token; returns a decision, never raises on input."""
        seq = _check_seq(seq)
        now_seq = _check_seq(now_seq, "now_seq")
        audience = _check_str(audience, "audience")

        def invalid(reason: str) -> VerificationReport:
            return VerificationReport(
                valid=False, reason=reason, claims=None, seq=seq
            )

        if not isinstance(token, str):
            return invalid("not-a-string")
        parts = token.split(".")
        if len(parts) != 3:
            return invalid("malformed")
        try:
            header_raw = _b64url_decode(parts[0])
            payload_raw = _b64url_decode(parts[1])
            sig = _b64url_decode(parts[2])
        except Exception:
            return invalid("bad-encoding")
        import json as _json

        try:
            header = _json.loads(header_raw.decode("utf-8"))
            claims = _json.loads(payload_raw.decode("utf-8"))
        except Exception:
            return invalid("bad-json")
        if not isinstance(claims, dict):
            return invalid("bad-claims")
        if header.get("alg") != "HS256":
            return invalid("unsupported-alg")
        expected = self._sign(f"{parts[0]}.{parts[1]}".encode("ascii"))
        if not hmac.compare_digest(expected, sig):
            return invalid("bad-signature")
        if claims.get("iss") != self._issuer.rstrip("/"):
            return invalid("issuer-mismatch")
        if claims.get("aud") != audience:
            return invalid("audience-mismatch")
        exp = claims.get("exp")
        if isinstance(exp, bool) or not isinstance(exp, int):
            return invalid("bad-exp")
        if now_seq >= exp:
            return invalid("expired")
        return VerificationReport(
            valid=True, reason="ok", claims=dict(claims), seq=seq
        )

    # -- userinfo ----------------------------------------------------------

    def userinfo(self, access_token_id: str, seq: int, now_seq: int) -> UserInfo:
        """Release standard claims for a live, unrevoked access token."""
        with self._lock:
            seq = _check_seq(seq)
            self._bump_seq(seq)
            now_seq = _check_seq(now_seq, "now_seq")
            token_id = _check_str(access_token_id, "access-token")
            rec = self._access.get(token_id)
            if rec is None:
                raise UnknownTokenError(f"{ERROR_PREFIX}unknown-token")
            if token_id in self._revoked:
                raise RevokedTokenError(f"{ERROR_PREFIX}token-revoked")
            if now_seq >= rec.exp_seq:
                raise ExpiredTokenError(f"{ERROR_PREFIX}token-expired")
            profile = dict(self._profiles.get(rec.user_id, {}))
            claims: Dict[str, Any] = {"sub": rec.user_id}
            claims.update(profile)
            claims.setdefault("email_verified", False)
            digest = _sha256_pin(
                jcs_canonical_json({"sub": rec.user_id, "claims": claims})
            )
            return UserInfo(sub=rec.user_id, claims=claims, digest=digest, seq=seq)

    # -- refresh & revocation ------------------------------------------------

    def exchange_refresh(
        self, refresh_token_id: str, seq: int, now_seq: int
    ) -> TokenSet:
        """Rotate a refresh token: new tokens, old one burned."""
        with self._lock:
            seq = _check_seq(seq)
            self._bump_seq(seq)
            now_seq = _check_seq(now_seq, "now_seq")
            token_id = _check_str(refresh_token_id, "refresh-token")
            if token_id in self._revoked:
                raise RevokedTokenError(f"{ERROR_PREFIX}refresh-token-revoked")
            rec = self._refresh.get(token_id)
            if rec is None:
                raise UnknownTokenError(f"{ERROR_PREFIX}unknown-refresh-token")
            # Burn the old refresh token (rotation).
            del self._refresh[token_id]
            self._revoked[token_id] = RevocationRecord(
                token_id=token_id,
                token_type="refresh_token",
                digest=_sha256_pin(b"revoked:" + token_id.encode()),
                seq=seq,
            )

            exp_seq = now_seq + DEFAULT_TOKEN_LIFETIME_SEQS
            claims: Dict[str, Any] = {
                "iss": self._issuer.rstrip("/"),
                "sub": rec.user_id,
                "aud": rec.client_id,
                "exp": exp_seq,
                "iat": now_seq,
                "auth_time": rec.seq,
                "acr": "0",
                "scope": " ".join(rec.scopes),
            }
            jwt = self._mint_jwt(claims)
            id_digest = _sha256_pin(jcs_canonical_json(claims))
            id_token = IDToken(token=jwt, claims=dict(claims), digest=id_digest, seq=seq)

            at_id = self._mint("at")
            at_digest = _sha256_pin(
                jcs_canonical_json(
                    {
                        "token_id": at_id,
                        "client_id": rec.client_id,
                        "user_id": rec.user_id,
                        "scopes": list(rec.scopes),
                        "exp_seq": exp_seq,
                    }
                )
            )
            access = AccessTokenRecord(
                token_id=at_id,
                client_id=rec.client_id,
                user_id=rec.user_id,
                scopes=rec.scopes,
                exp_seq=exp_seq,
                digest=at_digest,
                seq=seq,
            )
            self._access[at_id] = access

            rt_id = self._mint("rt")
            rt_digest = _sha256_pin(
                jcs_canonical_json(
                    {
                        "token_id": rt_id,
                        "client_id": rec.client_id,
                        "user_id": rec.user_id,
                        "scopes": list(rec.scopes),
                    }
                )
            )
            refresh = RefreshTokenRecord(
                token_id=rt_id,
                client_id=rec.client_id,
                user_id=rec.user_id,
                scopes=rec.scopes,
                digest=rt_digest,
                seq=seq,
            )
            self._refresh[rt_id] = refresh

            digest = _sha256_pin(
                jcs_canonical_json(
                    {"id_token": id_digest, "access": at_digest, "refresh": rt_digest}
                )
            )
            return TokenSet(
                id_token=id_token,
                access_token=access,
                refresh_token=refresh,
                digest=digest,
                seq=seq,
            )

    def revoke(self, token_id: str, seq: int) -> RevocationRecord:
        """Revoke an access or refresh token (fail-closed on unknown)."""
        with self._lock:
            seq = _check_seq(seq)
            self._bump_seq(seq)
            token_id = _check_str(token_id, "token")
            if token_id in self._access:
                token_type = "access_token"
            elif token_id in self._refresh:
                token_type = "refresh_token"
            else:
                raise UnknownTokenError(f"{ERROR_PREFIX}unknown-token")
            if token_id in self._revoked:
                raise RevokedTokenError(f"{ERROR_PREFIX}already-revoked")
            rec = RevocationRecord(
                token_id=token_id,
                token_type=token_type,
                digest=_sha256_pin(b"revoked:" + token_id.encode()),
                seq=seq,
            )
            self._revoked[token_id] = rec
            return rec

    # -- views ---------------------------------------------------------------

    def clients(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._clients))

    def is_revoked(self, token_id: str) -> bool:
        with self._lock:
            return token_id in self._revoked


# ---------------------------------------------------------------------------
# Audit event shaper
# ---------------------------------------------------------------------------


def oidc_provider_audit_event(
    kind: str, seq: int, detail: Optional[Mapping[str, Any]] = None
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for OIDC provider events."""
    seq = _check_seq(seq)
    if kind not in _AUDIT_KINDS:
        raise OIDCError(f"{ERROR_PREFIX}unknown-audit-kind: {kind!r}")
    clean: Dict[str, Any] = {}
    if detail:
        for k, v in detail.items():
            if not isinstance(k, str):
                raise OIDCError(f"{ERROR_PREFIX}bad-audit-key")
            clean[k] = v
    # Never allow secrets or raw tokens into the audit stream.
    for banned in ("signing_secret", "secret", "token", "refresh_token"):
        if banned in clean:
            raise OIDCError(f"{ERROR_PREFIX}audit-would-leak-secret")
    return {
        "schema": "audit.ndjson/1",
        "kind": f"oidc-provider.{kind}",
        "seq": seq,
        "detail": clean,
        "module": OIDC_PROVIDER_VERSION,
    }


def main() -> None:
    p = OIDCProvider("https://idp.example.com", b"0" * 32)
    doc = p.discover()
    assert doc.issuer == "https://idp.example.com"
    client = p.register_client(
        "web", ["https://app.example.com/cb"], ["openid", "profile", "email"], 1
    )
    assert client.client_id == "web"
    p.set_profile("alice", {"name": "Alice", "email": "a@example.com"}, 2)
    code = p.authorize("web", "alice", ["openid", "profile"], 3, nonce="n-1")
    tokens = p.id_token(code.code, 4, now_seq=10)
    rep = p.verify_id_token(tokens.id_token.token, "web", now_seq=11, seq=5)
    assert rep.valid and rep.claims["sub"] == "alice"
    info = p.userinfo(tokens.access_token.token_id, 6, now_seq=11)
    assert info.claims["name"] == "Alice"
    print("oidc-provider OK: discover, register, authorize, tokens, verify, userinfo")


if __name__ == "__main__":
    main()
