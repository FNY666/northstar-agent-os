"""OAuth2 provider: authorization-code + PKCE as deterministic bookkeeping.

Research note: OAuth 2.0 (RFC 6749) is the delegation protocol behind
"sign in with" buttons and third-party API access. The authorization-code
flow exists because the front channel (browser) is untrusted: the code is a
short-lived, single-use, redirect-bound credential exchanged for tokens on
the back channel, so tokens never transit the browser. PKCE (RFC 7636) adds
proof-of-possession for public clients (mobile/SPA) that cannot keep a
secret: the client commits to ``code_challenge`` at authorize time and
reveals ``code_verifier`` at token time.

The security shape is well studied (RFC 6749; OAuth 2.0 Security Best
Current Practice, draft-ietf-oauth-security-topics): the load-bearing
invariants are

* **exact redirect-URI matching** — a prefix or substring match lets an
  attacker register ``evil.com/?redirect_uri=victim.com.evil.com`` and
  steal codes (open-redirect code theft);
* **single-use codes** — replaying a code must fail, and on second
  presentation the whole grant is suspect;
* **client authentication for confidential clients** — the back-channel
  exchange must prove the client is who it claims to be;
* **PKCE binding for public clients** — without a verifier check, anyone
  who intercepts the code (malicious app on the device, leaked logs) can
  redeem it;
* **refresh-token rotation** — reusing a rotated refresh token signals
  theft; the safe response is to revoke the whole token family.

This module books those invariants. It owns the *grant ledger*, not the
network: ``authorize()`` mints codes, ``token()`` redeems them,
``refresh()`` rotates, ``revoke()`` kills. Tokens are opaque
HMAC-derived strings (deterministic per ``session_secret`` + counter, so
audit replay is exact); the host performs HTTP and enforces TLS.

* **Client registration** — ``register_client(client_id, redirect_uris,
  seq, client_type=..., secret=..., scope=...)`` pins one client. Exactly
  one redirect URI must match at authorize time (fragments refused at
  registration — RFC 6749 section 3.1.2). Confidential clients hold a
  secret (caller-supplied or HMAC-derived, never emitted); public clients
  hold none and *must* use PKCE.
* **Authorize** — ``authorize(client_id, redirect_uri, response_type,
  seq, ...)`` requires ``response_type="code"`` and an exactly-registered
  ``redirect_uri``. ``state`` is echoed verbatim (the CSRF binding is the
  caller's job to check). Requested scope must be a subset of the
  registered scope.
* **Token exchange** — ``token(code, client_id, seq, ...)`` verifies, in
  order: the code exists, is unused, and is unexpired; the ``client_id``
  matches the code's client; the ``redirect_uri`` (when supplied) matches
  the code's; a confidential client's secret verifies with
  ``hmac.compare_digest``; the PKCE verifier satisfies the challenge
  (``S256``: ``base64url(sha256(verifier)) == challenge``;
  ``plain``: equality; verifier length 43-128 per RFC 7636). The code is
  consumed *before* tokens mint — a failure after consumption never
  leaves a live code.
* **Refresh rotation** — ``refresh(refresh_token, client_id, seq, ...)``
  mints a fresh access/refresh pair and invalidates the presented refresh
  token. Presenting an already-rotated token raises ``TokenReuseError``
  and revokes every token in that family (theft response).
* **Lifetimes** — caller-supplied int seqs (no wall-clock): codes live
  ``code_lifetime_seqs``, access tokens ``access_token_lifetime_seqs``.
  A caller seq that moves backwards is refused fail-closed (a lying
  clock must not resurrect expired codes).

Honest scope: books *host-reported* grant events; cannot prove the real
user consented, cannot observe the browser, cannot stop a stolen token
from being used until ``revoke()`` is called; ``S256`` here is real
SHA-256 but token "randomness" is HMAC-deterministic, not a CSPRNG —
fine for a ledger, not for a production issuer. Scope strings are
permissions *claimed*, never enforced on a resource server.

Version pin: oauth2-provider.v1
Schema pin: northstar.oauth2-provider.v1
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import threading
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
OAUTH2_PROVIDER_VERSION = "oauth2-provider.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.oauth2-provider.v1"

#: Supported response type (RFC 6749 section 3.1.1).
RESPONSE_TYPE_CODE = "code"

#: Supported grant types.
GRANT_AUTHORIZATION_CODE = "authorization_code"
GRANT_REFRESH_TOKEN = "refresh_token"

#: Client types (RFC 6749 section 2.1).
CLIENT_CONFIDENTIAL = "confidential"
CLIENT_PUBLIC = "public"

#: PKCE challenge methods (RFC 7636 section 4.2).
PKCE_S256 = "S256"
PKCE_PLAIN = "plain"

#: Token type issued (RFC 6749 section 7.1).
TOKEN_TYPE_BEARER = "Bearer"

#: RFC 7636 section 4.1: verifier is 43-128 chars of [A-Z a-z 0-9 - . _ ~].
_PKCE_VERIFIER_MIN = 43
_PKCE_VERIFIER_MAX = 128


class OAuth2Error(Exception):
    """Base error for the OAuth2 provider."""


class DuplicateClientError(OAuth2Error):
    """A client_id is already registered."""


class UnknownClientError(OAuth2Error):
    """No client with this id is registered."""


class RedirectMismatchError(OAuth2Error):
    """redirect_uri is not exactly one of the registered URIs."""


class InvalidGrantError(OAuth2Error):
    """The authorization code is unknown, used, expired, or mismatched."""


class InvalidClientError(OAuth2Error):
    """Client authentication failed (bad secret)."""


class PKCEError(OAuth2Error):
    """PKCE challenge/verifier check failed or was required but absent."""


class TokenReuseError(OAuth2Error):
    """A rotated refresh token was presented again: possible theft."""


class UnknownTokenError(OAuth2Error):
    """No such access or refresh token is known."""


class ExpiredTokenError(OAuth2Error):
    """The token is known but past its lifetime."""


class ScopeError(OAuth2Error):
    """Requested scope exceeds what was granted/registered."""


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError("seq must be an int")
    if seq < 0:
        raise ValueError("seq must be non-negative")
    return seq


def _check_str(value: Any, name: str, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or isinstance(value, bool):
        raise TypeError(f"{name} must be a str")
    if not allow_empty and not value:
        raise ValueError(f"{name} must be non-empty")
    return value


def _digest(body: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(body)).hexdigest()


def _check_scope(scope: Any, name: str = "scope") -> Tuple[str, ...]:
    if not isinstance(scope, (tuple, list)):
        raise TypeError(f"{name} must be a tuple/list of scope tokens")
    out = []
    for token in scope:
        if not isinstance(token, str) or isinstance(token, bool) or not token:
            raise TypeError(f"{name} tokens must be non-empty strings")
        if any(c in token for c in (" ", "\t", "\n", "\r")):
            raise ValueError(f"{name} token {token!r} contains whitespace")
        out.append(token)
    return tuple(out)


def _pkce_s256_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _check_verifier(verifier: Any) -> str:
    if not isinstance(verifier, str) or isinstance(verifier, bool):
        raise TypeError("code_verifier must be a str")
    if not (_PKCE_VERIFIER_MIN <= len(verifier) <= _PKCE_VERIFIER_MAX):
        raise PKCEError(
            f"code_verifier must be {_PKCE_VERIFIER_MIN}-{_PKCE_VERIFIER_MAX} chars"
        )
    try:
        verifier.encode("ascii")
    except UnicodeEncodeError:
        raise PKCEError("code_verifier must be ASCII")
    return verifier


@dataclass(frozen=True)
class ClientRecord:
    """Pinned registration of one OAuth2 client."""

    client_id: str
    client_type: str
    redirect_uris: Tuple[str, ...]
    scope: Tuple[str, ...]
    digest: str
    version: str = OAUTH2_PROVIDER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "client_id": self.client_id,
            "client_type": self.client_type,
            "redirect_uris": list(self.redirect_uris),
            "scope": list(self.scope),
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class AuthorizationCode:
    """A single-use, redirect-bound authorization code."""

    code: str
    client_id: str
    redirect_uri: str
    scope: Tuple[str, ...]
    state: Optional[str]
    code_challenge: Optional[str]
    code_challenge_method: Optional[str]
    issued_seq: int
    expires_seq: int
    digest: str
    version: str = OAUTH2_PROVIDER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": list(self.scope),
            "state": self.state,
            "code_challenge_method": self.code_challenge_method,
            "issued_seq": self.issued_seq,
            "expires_seq": self.expires_seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class TokenSet:
    """An issued access/refresh token pair."""

    access_token: str
    token_type: str
    expires_in_seqs: int
    expires_seq: int
    refresh_token: str
    scope: Tuple[str, ...]
    client_id: str
    digest: str
    version: str = OAUTH2_PROVIDER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_in_seqs": self.expires_in_seqs,
            "expires_seq": self.expires_seq,
            "refresh_token": self.refresh_token,
            "scope": list(self.scope),
            "client_id": self.client_id,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class TokenInfo:
    """Introspection view of an access token."""

    access_token: str
    client_id: str
    scope: Tuple[str, ...]
    expires_seq: int
    active: bool
    digest: str
    version: str = OAUTH2_PROVIDER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "access_token": self.access_token,
            "client_id": self.client_id,
            "scope": list(self.scope),
            "expires_seq": self.expires_seq,
            "active": self.active,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class RevocationRecord:
    """Frozen record of a revocation."""

    token: str
    kind: str  # "access" | "refresh"
    seq: int
    digest: str
    version: str = OAUTH2_PROVIDER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "token": self.token,
            "kind": self.kind,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


_AUDIT_KINDS = frozenset(
    {
        "client-registered",
        "code-issued",
        "token-issued",
        "token-refreshed",
        "token-revoked",
        "family-revoked",
        "rejected",
    }
)


class OAuth2Provider:
    """Simulated OAuth2 authorization server: the grant ledger."""

    def __init__(
        self,
        session_secret: bytes,
        code_lifetime_seqs: int = 600,
        access_token_lifetime_seqs: int = 3600,
    ) -> None:
        if not isinstance(session_secret, (bytes, bytearray)) or not session_secret:
            raise TypeError("session_secret must be non-empty bytes")
        if isinstance(code_lifetime_seqs, bool) or not isinstance(
            code_lifetime_seqs, int
        ):
            raise TypeError("code_lifetime_seqs must be an int")
        if code_lifetime_seqs <= 0:
            raise ValueError("code_lifetime_seqs must be positive")
        if isinstance(access_token_lifetime_seqs, bool) or not isinstance(
            access_token_lifetime_seqs, int
        ):
            raise TypeError("access_token_lifetime_seqs must be an int")
        if access_token_lifetime_seqs <= 0:
            raise ValueError("access_token_lifetime_seqs must be positive")
        self._secret = bytes(session_secret)
        self._code_lifetime = code_lifetime_seqs
        self._at_lifetime = access_token_lifetime_seqs
        self._lock = threading.RLock()
        self._clients: Dict[str, ClientRecord] = {}
        self._client_secrets: Dict[str, bytes] = {}
        self._codes: Dict[str, AuthorizationCode] = {}
        self._used_codes: set = set()
        self._access: Dict[str, Dict[str, Any]] = {}  # token -> meta
        self._refresh: Dict[str, Dict[str, Any]] = {}  # token -> meta
        self._rotated_refresh: set = set()  # presented-again => theft
        self._token_family: Dict[str, str] = {}  # every minted token -> family
        self._counter = 0
        self._last_seq = -1

    # -- internals -----------------------------------------------------

    def _check_seq_monotonic(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise ValueError("seq must strictly increase")
        self._last_seq = seq
        return seq

    def _mint(self, kind: str) -> str:
        self._counter += 1
        mac = hmac.new(
            self._secret,
            f"{kind}:{self._counter}".encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        return f"{kind}_{mac[:32]}"

    def _get_client(self, client_id: str) -> ClientRecord:
        try:
            return self._clients[client_id]
        except KeyError:
            raise UnknownClientError(f"unknown client {client_id!r}")

    def _auth_confidential(self, client_id: str, client_secret: Any) -> None:
        expected = self._client_secrets.get(client_id)
        if expected is None:
            return  # public client: nothing to check
        if not isinstance(client_secret, (str, bytes)) or isinstance(
            client_secret, bool
        ):
            raise InvalidClientError("client_secret required for confidential client")
        presented = (
            client_secret.encode("utf-8")
            if isinstance(client_secret, str)
            else bytes(client_secret)
        )
        if not hmac.compare_digest(presented, expected):
            raise InvalidClientError("client authentication failed")

    # -- client registration --------------------------------------------

    def register_client(
        self,
        client_id: str,
        redirect_uris: Tuple[str, ...],
        seq: int,
        client_type: str = CLIENT_CONFIDENTIAL,
        secret: Optional[Any] = None,
        scope: Tuple[str, ...] = (),
    ) -> ClientRecord:
        """Pin one OAuth2 client and its exactly-matchable redirect URIs."""
        with self._lock:
            seq = self._check_seq_monotonic(seq)
            client_id = _check_str(client_id, "client_id")
            if client_type not in (CLIENT_CONFIDENTIAL, CLIENT_PUBLIC):
                raise ValueError("client_type must be 'confidential' or 'public'")
            if not isinstance(redirect_uris, (tuple, list)) or not redirect_uris:
                raise TypeError("redirect_uris must be a non-empty tuple/list")
            uris = tuple(_check_str(u, "redirect_uri") for u in redirect_uris)
            if len(set(uris)) != len(uris):
                raise ValueError("redirect_uris must be unique")
            for uri in uris:
                if "#" in uri:
                    raise ValueError("redirect_uri must not contain a fragment")
            scope_t = _check_scope(scope)
            if client_id in self._clients:
                raise DuplicateClientError(f"client {client_id!r} already registered")
            secret_bytes: Optional[bytes] = None
            if client_type == CLIENT_CONFIDENTIAL:
                if secret is None:
                    secret_bytes = hmac.new(
                        self._secret,
                        b"client-secret:" + client_id.encode("utf-8"),
                        hashlib.sha256,
                    ).digest()
                else:
                    if not isinstance(secret, (str, bytes)) or isinstance(secret, bool):
                        raise TypeError("secret must be str or bytes")
                    secret_bytes = (
                        secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
                    )
                    if not secret_bytes:
                        raise ValueError("secret must be non-empty")
                self._client_secrets[client_id] = secret_bytes
            elif secret is not None:
                raise ValueError("public clients must not carry a secret")
            record = ClientRecord(
                client_id=client_id,
                client_type=client_type,
                redirect_uris=uris,
                scope=scope_t,
                digest=_digest(
                    {
                        "client_id": client_id,
                        "client_type": client_type,
                        "redirect_uris": list(uris),
                        "scope": list(scope_t),
                    }
                ),
            )
            self._clients[client_id] = record
            return record

    def client(self, client_id: str) -> ClientRecord:
        """Return the pinned registration for a client."""
        with self._lock:
            return self._get_client(_check_str(client_id, "client_id"))

    # -- authorization endpoint ------------------------------------------

    def authorize(
        self,
        client_id: str,
        redirect_uri: str,
        response_type: str,
        seq: int,
        scope: Tuple[str, ...] = (),
        state: Optional[str] = None,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
    ) -> AuthorizationCode:
        """Mint a single-use authorization code (the front-channel step)."""
        with self._lock:
            seq = self._check_seq_monotonic(seq)
            client = self._get_client(_check_str(client_id, "client_id"))
            redirect_uri = _check_str(redirect_uri, "redirect_uri")
            if redirect_uri not in client.redirect_uris:
                # Exact match only: no prefix/substring games (open-redirect
                # code theft lives here).
                raise RedirectMismatchError("redirect_uri is not registered")
            if response_type != RESPONSE_TYPE_CODE:
                raise InvalidGrantError("only response_type='code' is supported")
            scope_t = _check_scope(scope)
            if client.scope and not set(scope_t) <= set(client.scope):
                raise ScopeError("requested scope exceeds registered scope")
            if state is not None:
                state = _check_str(state, "state", allow_empty=True)
                if len(state) > 1024:
                    raise ValueError("state must be at most 1024 chars")
            method: Optional[str] = None
            if code_challenge is not None:
                if not isinstance(code_challenge, str) or isinstance(
                    code_challenge, bool
                ):
                    raise TypeError("code_challenge must be a str")
                if not (43 <= len(code_challenge) <= 128):
                    raise PKCEError("code_challenge must be 43-128 chars")
                method = code_challenge_method or PKCE_PLAIN
                if method not in (PKCE_S256, PKCE_PLAIN):
                    raise PKCEError("code_challenge_method must be 'S256' or 'plain'")
            elif client.client_type == CLIENT_PUBLIC:
                # Public clients cannot authenticate at the token endpoint;
                # PKCE is their only code-binding. Mandatory.
                raise PKCEError("public clients must supply code_challenge (PKCE)")
            code = self._mint("ac")
            record = AuthorizationCode(
                code=code,
                client_id=client.client_id,
                redirect_uri=redirect_uri,
                scope=scope_t,
                state=state,
                code_challenge=code_challenge,
                code_challenge_method=method,
                issued_seq=seq,
                expires_seq=seq + self._code_lifetime,
                digest=_digest(
                    {
                        "code": code,
                        "client_id": client.client_id,
                        "redirect_uri": redirect_uri,
                        "scope": list(scope_t),
                        "issued_seq": seq,
                    }
                ),
            )
            self._codes[code] = record
            return record

    # -- token endpoint ---------------------------------------------------

    def token(
        self,
        code: str,
        client_id: str,
        seq: int,
        redirect_uri: Optional[str] = None,
        client_secret: Optional[Any] = None,
        code_verifier: Optional[str] = None,
    ) -> TokenSet:
        """Redeem an authorization code for tokens (the back-channel step)."""
        with self._lock:
            seq = self._check_seq_monotonic(seq)
            code = _check_str(code, "code")
            client_id = _check_str(client_id, "client_id")
            grant = self._codes.get(code)
            if grant is None or code in self._used_codes:
                raise InvalidGrantError("authorization code unknown or already used")
            if seq > grant.expires_seq:
                # Consume it anyway: an expired code must never become valid.
                self._used_codes.add(code)
                del self._codes[code]
                raise InvalidGrantError("authorization code expired")
            if grant.client_id != client_id:
                raise InvalidGrantError("code was issued to a different client")
            if redirect_uri is not None and redirect_uri != grant.redirect_uri:
                raise RedirectMismatchError("redirect_uri does not match the code")
            self._auth_confidential(client_id, client_secret)
            if grant.code_challenge is not None:
                if code_verifier is None:
                    raise PKCEError("code_verifier required for this code")
                verifier = _check_verifier(code_verifier)
                if grant.code_challenge_method == PKCE_S256:
                    if not hmac.compare_digest(
                        _pkce_s256_challenge(verifier), grant.code_challenge
                    ):
                        raise PKCEError("PKCE S256 verifier mismatch")
                else:
                    if not hmac.compare_digest(verifier, grant.code_challenge):
                        raise PKCEError("PKCE plain verifier mismatch")
            # Consume before minting: no path leaves a live code behind.
            self._used_codes.add(code)
            del self._codes[code]
            return self._mint_tokens(
                client_id=client_id, scope=grant.scope, seq=seq, family=None
            )

    def _mint_tokens(
        self,
        client_id: str,
        scope: Tuple[str, ...],
        seq: int,
        family: Optional[str],
    ) -> TokenSet:
        access = self._mint("at")
        refresh = self._mint("rt")
        family = family or self._mint("fam")
        expires_seq = seq + self._at_lifetime
        body = {
            "access_token": access,
            "client_id": client_id,
            "scope": list(scope),
            "expires_seq": expires_seq,
            "refresh_token": refresh,
            "family": family,
        }
        digest = _digest(body)
        self._access[access] = {
            "client_id": client_id,
            "scope": scope,
            "expires_seq": expires_seq,
            "family": family,
            "digest": digest,
        }
        self._refresh[refresh] = {
            "client_id": client_id,
            "scope": scope,
            "family": family,
            "digest": digest,
        }
        self._token_family[access] = family
        self._token_family[refresh] = family
        return TokenSet(
            access_token=access,
            token_type=TOKEN_TYPE_BEARER,
            expires_in_seqs=self._at_lifetime,
            expires_seq=expires_seq,
            refresh_token=refresh,
            scope=scope,
            client_id=client_id,
            digest=digest,
        )

    def refresh(
        self,
        refresh_token: str,
        client_id: str,
        seq: int,
        client_secret: Optional[Any] = None,
        scope: Optional[Tuple[str, ...]] = None,
    ) -> TokenSet:
        """Rotate a refresh token into a fresh token pair."""
        with self._lock:
            seq = self._check_seq_monotonic(seq)
            refresh_token = _check_str(refresh_token, "refresh_token")
            client_id = _check_str(client_id, "client_id")
            if refresh_token in self._rotated_refresh:
                # Reuse of a rotated token signals theft: kill the family.
                self._revoke_family_of(refresh_token, seq)
                raise TokenReuseError(
                    "refresh token already rotated; family revoked"
                )
            meta = self._refresh.get(refresh_token)
            if meta is None:
                raise UnknownTokenError("unknown refresh token")
            if meta["client_id"] != client_id:
                raise InvalidGrantError("refresh token belongs to a different client")
            self._auth_confidential(client_id, client_secret)
            scope_t = meta["scope"] if scope is None else _check_scope(scope)
            if not set(scope_t) <= set(meta["scope"]):
                raise ScopeError("requested scope exceeds granted scope")
            # Rotate: the presented token dies here.
            family = meta["family"]
            del self._refresh[refresh_token]
            self._rotated_refresh.add(refresh_token)
            return self._mint_tokens(
                client_id=client_id, scope=scope_t, seq=seq, family=family
            )

    def _revoke_family_of(self, refresh_token: str, seq: int) -> None:
        # The rotated token is already gone from _refresh, so the family
        # comes from the persistent token->family map.
        family = self._token_family.get(refresh_token)
        if family is None:
            return
        for store in (self._refresh, self._access):
            for token in [t for t, m in store.items() if m.get("family") == family]:
                del store[token]

    # -- revocation / introspection ----------------------------------------

    def revoke(self, token: str, seq: int) -> RevocationRecord:
        """Revoke one access or refresh token (RFC 7009 discipline)."""
        with self._lock:
            seq = self._check_seq_monotonic(seq)
            token = _check_str(token, "token")
            if token in self._access:
                kind = "access"
                del self._access[token]
            elif token in self._refresh:
                kind = "refresh"
                del self._refresh[token]
            else:
                raise UnknownTokenError("unknown token")
            record = RevocationRecord(
                token=token,
                kind=kind,
                seq=seq,
                digest=_digest({"token": token, "kind": kind, "seq": seq}),
            )
            return record

    def token_info(self, access_token: str, seq: int) -> TokenInfo:
        """Introspect an access token: active only if known and unexpired."""
        with self._lock:
            seq = self._check_seq_monotonic(seq)
            access_token = _check_str(access_token, "access_token")
            meta = self._access.get(access_token)
            if meta is None:
                raise UnknownTokenError("unknown access token")
            active = seq <= meta["expires_seq"]
            return TokenInfo(
                access_token=access_token,
                client_id=meta["client_id"],
                scope=meta["scope"],
                expires_seq=meta["expires_seq"],
                active=active,
                digest=_digest(
                    {
                        "access_token": access_token,
                        "client_id": meta["client_id"],
                        "active": active,
                    }
                ),
            )


def oauth2_provider_audit_event(
    kind: str,
    seq: int,
    client: Optional[ClientRecord] = None,
    code: Optional[AuthorizationCode] = None,
    tokens: Optional[TokenSet] = None,
    revocation: Optional[RevocationRecord] = None,
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for a provider step.

    ``kind`` is one of ``client-registered`` / ``code-issued`` /
    ``token-issued`` / ``token-refreshed`` / ``token-revoked`` /
    ``family-revoked`` / ``rejected``. Secrets, verifiers, and token
    values never appear — only ids and digest pins.
    """
    if kind not in _AUDIT_KINDS:
        raise ValueError(f"kind must be one of {sorted(_AUDIT_KINDS)}")
    _check_seq(seq)
    if client is not None and not isinstance(client, ClientRecord):
        raise TypeError("client must be a ClientRecord")
    if code is not None and not isinstance(code, AuthorizationCode):
        raise TypeError("code must be an AuthorizationCode")
    if tokens is not None and not isinstance(tokens, TokenSet):
        raise TypeError("tokens must be a TokenSet")
    if revocation is not None and not isinstance(revocation, RevocationRecord):
        raise TypeError("revocation must be a RevocationRecord")
    record: Dict[str, Any] = {
        "event": f"oauth2-provider-{kind}",
        "audit_seq": seq,
        "schema": SCHEMA_PIN,
    }
    if client is not None:
        record["client_id"] = client.client_id
        record["client_type"] = client.client_type
        record["client_digest"] = client.digest
    if code is not None:
        record["code_digest"] = code.digest
        record["client_id"] = code.client_id
        record["expires_seq"] = code.expires_seq
    if tokens is not None:
        record["token_digest"] = tokens.digest
        record["client_id"] = tokens.client_id
        record["expires_seq"] = tokens.expires_seq
    if revocation is not None:
        record["kind"] = revocation.kind
        record["revocation_digest"] = revocation.digest
    return record


def main() -> None:
    """Self-check: register, authorize (PKCE), exchange, refresh, revoke."""
    provider = OAuth2Provider(session_secret=b"self-check-secret")
    client = provider.register_client(
        "webapp",
        ("https://app.example.com/callback",),
        seq=1,
        scope=("read", "write"),
    )
    assert client.digest.startswith("sha256:")
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = _pkce_s256_challenge(verifier)
    grant = provider.authorize(
        "webapp",
        "https://app.example.com/callback",
        "code",
        seq=2,
        scope=("read",),
        state="xyz",
        code_challenge=challenge,
        code_challenge_method="S256",
    )
    assert grant.state == "xyz"
    # Confidential client authenticates with its derived secret.
    secret = provider._client_secrets["webapp"]
    tokens = provider.token(
        grant.code, "webapp", seq=3, client_secret=secret, code_verifier=verifier
    )
    assert tokens.token_type == "Bearer"
    info = provider.token_info(tokens.access_token, seq=4)
    assert info.active and info.scope == ("read",)
    rotated = provider.refresh(tokens.refresh_token, "webapp", seq=5, client_secret=secret)
    assert rotated.access_token != tokens.access_token
    try:
        provider.refresh(tokens.refresh_token, "webapp", seq=6, client_secret=secret)
    except TokenReuseError:
        pass
    else:
        raise AssertionError("rotated refresh token must not be reusable")
    print("oauth2-provider OK: register, authorize, PKCE, exchange, rotate, reuse-kill")


if __name__ == "__main__":
    main()
