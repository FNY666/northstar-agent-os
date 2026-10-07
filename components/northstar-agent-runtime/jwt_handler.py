"""HMAC-based JSON Web Token (JWT) handler.

HS256-shaped ``sign`` / ``verify`` / ``decode`` bookkeeping over a
shared secret, following the JWT shape from RFC 7519:

- ``sign(claims, seq)`` -> frozen ``SignedToken``: the compact
  ``header.payload.signature`` serialization with a deterministic
  ``sha256:`` digest pin over the signing input.
- ``verify(token, seq)`` -> frozen ``VerifiedClaims``: signature check
  with ``hmac.compare_digest``, then claim validation (``iss``,
  ``aud``, ``exp``, ``nbf``) fail-closed.
- ``decode(token)`` -> frozen ``DecodedToken``: header + payload parsed
  *without* signature verification, for inspection only.

Standard claims are expressed in caller-supplied integer seqs
(no wall-clock): ``iat``/``exp``/``nbf`` are seq numbers, never
Unix timestamps. ``ttl_seqs`` bounds the lifetime at issue time;
``verify`` refuses an ``exp``-less token fail-closed (no expiry is a
misconfiguration, not a feature) and refuses ``nbf`` in the future.

Fail-closed security posture:

1. ``alg`` is pinned to ``HS256``. Any token whose header names another
   algorithm - including the classic ``alg=none`` confusion attack -
   raises ``MalformedTokenError`` before any key material is touched.
2. Signatures are verified with ``hmac.compare_digest``; a mismatch is
   ``SignatureError``, never a silent ``None``.
3. ``iss`` must equal the handler's issuer (when configured) and
   ``aud`` must match (when configured) - cross-issuer and
   cross-audience replay is refused.
4. ``exp`` at or before the verifying seq is ``ExpiredTokenError``;
   ``nbf`` after the verifying seq is ``NotYetValidError``.
5. A ``revoke(jti, seq)`` registry makes previously issued tokens stop
   verifying with ``RevokedTokenError``.

Honest scope: bookkeeping simulation of the JWT API shape, not a
security boundary. The MAC is real HMAC-SHA256 but the secret lives in
process memory; caller-supplied claims are *reported* values, and a
verified token proves "the key holder attested these claims at some
seq", never that the claims are true. Host-reported seqs are the only
clock - a lying host gets a consistent ledger of lies (GIGO).
Secrets are never written into records, ``as_dict()`` views, or audit
events: only ``sha256:`` digest pins cross the API boundary.

No wall-clock anywhere. All caller-supplied int seqs.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
JWT_HANDLER_VERSION = "jwt-handler.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.jwt-handler.v1"

#: Audit event schema pin.
AUDIT_SCHEMA = "audit.ndjson/1"

#: The only accepted JOSE algorithm.
ALGORITHM = "HS256"

#: Hard cap on token length accepted by verify/decode (guardrail).
MAX_TOKEN_BYTES = 64 * 1024

#: Hard cap on claim-map size accepted at sign/verify (guardrail).
MAX_CLAIMS = 256


class JWTError(Exception):
    """Base fail-closed JWT error."""


class MalformedTokenError(JWTError):
    """Not three base64url segments, bad JSON, non-mapping parts, wrong alg."""


class SignatureError(JWTError):
    """MAC mismatch - the token was not signed with this handler's secret."""


class ExpiredTokenError(JWTError):
    """Token expired at or before the verifying seq."""


class NotYetValidError(JWTError):
    """Token has nbf strictly after the verifying seq."""


class IssuerMismatchError(JWTError):
    """Token iss does not equal the handler's configured issuer."""


class AudienceMismatchError(JWTError):
    """Token aud does not match the handler's configured audience."""


class RevokedTokenError(JWTError):
    """Token jti was revoked with revoke()."""


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    if not isinstance(text, str) or not text:
        raise MalformedTokenError("empty segment")
    try:
        padded = text + "=" * (-len(text) % 4)
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:
        raise MalformedTokenError("segment is not base64url: %r" % text[:32]) from exc


def _check_seq(seq: int, what: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise JWTError("%s must be a non-negative int, got %r" % (what, seq))
    return seq


def _check_secret(secret: Any) -> bytes:
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    if not isinstance(secret, bytes) or len(secret) < 16:
        raise JWTError("secret must be bytes/str of at least 16 bytes")
    return secret


def _check_claims(claims: Any, what: str = "claims") -> Dict[str, Any]:
    if not isinstance(claims, Mapping) or len(claims) > MAX_CLAIMS:
        raise JWTError("%s must be a mapping with <= %d entries" % (what, MAX_CLAIMS))
    try:
        canonical = jcs_canonical_json(dict(claims))
    except Exception as exc:
        raise JWTError("%s must be JSON-canonicalizable: %s" % (what, exc)) from exc
    # Replay the digest to pin rejection of non-canonical values (NaN etc.).
    _ = hashlib.sha256(canonical).hexdigest()
    return dict(claims)


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class SignedToken:
    """Frozen issue record: the compact token plus identity pins."""

    token: str
    signing_input_digest: str
    payload_digest: str
    jti: str
    version: str = JWT_HANDLER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "token": self.token,
            "signing_input_digest": self.signing_input_digest,
            "payload_digest": self.payload_digest,
            "jti": self.jti,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class VerifiedClaims:
    """Frozen verification record: signature valid and claims validated."""

    claims: Mapping[str, Any]
    token_digest: str
    seq: int
    version: str = JWT_HANDLER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "claims": dict(self.claims),
            "token_digest": self.token_digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class DecodedToken:
    """Frozen parse record: header/payload decoded WITHOUT verification."""

    header: Mapping[str, Any]
    payload: Mapping[str, Any]
    version: str = JWT_HANDLER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "header": dict(self.header),
            "payload": dict(self.payload),
            "version": self.version,
            "schema": self.schema,
        }


class JWTHandler:
    """HMAC-SHA256 JWT issuer/verifier bound to one secret + issuer."""

    def __init__(
        self,
        secret: Any,
        issuer: str,
        *,
        audience: Optional[str] = None,
        default_ttl_seqs: int = 3600,
    ) -> None:
        self._secret = _check_secret(secret)
        if not isinstance(issuer, str) or not issuer:
            raise JWTError("issuer must be a non-empty str")
        if audience is not None and (not isinstance(audience, str) or not audience):
            raise JWTError("audience must be a non-empty str or None")
        if isinstance(default_ttl_seqs, bool) or not isinstance(default_ttl_seqs, int):
            raise JWTError("default_ttl_seqs must be a positive int")
        if default_ttl_seqs <= 0:
            raise JWTError("default_ttl_seqs must be a positive int")
        self._issuer = issuer
        self._audience = audience
        self._default_ttl_seqs = default_ttl_seqs
        self._lock = threading.RLock()
        self._counter = 0
        self._revoked: Dict[str, int] = {}

    # -- issue ---------------------------------------------------------

    def sign(
        self,
        claims: Mapping[str, Any],
        seq: int,
        *,
        ttl_seqs: Optional[int] = None,
        jti: Optional[str] = None,
    ) -> SignedToken:
        """Issue a compact HS256 token; standard claims pinned from seq."""
        with self._lock:
            seq = _check_seq(seq)
            body = _check_claims(claims)
            ttl = self._default_ttl_seqs if ttl_seqs is None else ttl_seqs
            if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl <= 0:
                raise JWTError("ttl_seqs must be a positive int")
            if jti is not None and (not isinstance(jti, str) or not jti):
                raise JWTError("jti must be a non-empty str or None")
            self._counter += 1
            token_jti = jti if jti is not None else "jti-%d-%d" % (seq, self._counter)

            header = {"alg": ALGORITHM, "typ": "JWT", "kid": "hs256-sim"}
            payload = dict(body)
            payload.setdefault("iss", self._issuer)
            payload.setdefault("iat", seq)
            payload.setdefault("nbf", seq)
            payload.setdefault("exp", seq + ttl)
            payload.setdefault("jti", token_jti)

            header_b64 = _b64url_encode(jcs_canonical_json(header))
            payload_b64 = _b64url_encode(jcs_canonical_json(payload))
            signing_input = ("%s.%s" % (header_b64, payload_b64)).encode("ascii")
            mac = hmac.new(self._secret, signing_input, hashlib.sha256).digest()
            token = "%s.%s.%s" % (header_b64, payload_b64, _b64url_encode(mac))
            if len(token) > MAX_TOKEN_BYTES:
                raise JWTError("token exceeds guardrail")
            return SignedToken(
                token=token,
                signing_input_digest=_digest(signing_input),
                payload_digest=_digest(jcs_canonical_json(payload)),
                jti=token_jti,
            )

    # -- verify ---------------------------------------------------------

    def _parse(self, token: Any) -> Tuple[Dict[str, Any], Dict[str, Any], bytes, bytes]:
        if not isinstance(token, str) or len(token) > MAX_TOKEN_BYTES or not token:
            raise MalformedTokenError("token must be a non-empty str")
        parts = token.split(".")
        if len(parts) != 3:
            raise MalformedTokenError("token must have exactly 3 segments")
        header_b64, payload_b64, sig_b64 = parts
        try:
            header = json.loads(_b64url_decode(header_b64).decode("utf-8"))
            payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        except (MalformedTokenError, UnicodeDecodeError, ValueError) as exc:
            raise MalformedTokenError("header/payload are not JSON: %s" % exc) from exc
        if not isinstance(header, dict) or not isinstance(payload, dict):
            raise MalformedTokenError("header/payload must be JSON objects")
        if header.get("alg") != ALGORITHM:
            raise MalformedTokenError("unsupported alg: %r (only HS256)" % header.get("alg"))
        sig = _b64url_decode(sig_b64)
        signing_input = ("%s.%s" % (header_b64, payload_b64)).encode("ascii")
        return header, payload, sig, signing_input

    def verify(self, token: str, seq: int) -> VerifiedClaims:
        """Verify signature + claims fail-closed; returns VerifiedClaims."""
        with self._lock:
            seq = _check_seq(seq)
            _, payload, sig, signing_input = self._parse(token)
            expected = hmac.new(self._secret, signing_input, hashlib.sha256).digest()
            if not hmac.compare_digest(sig, expected):
                raise SignatureError("signature mismatch")

            iss = payload.get("iss")
            if iss != self._issuer:
                raise IssuerMismatchError("iss %r != %r" % (iss, self._issuer))
            if self._audience is not None:
                aud = payload.get("aud")
                auds = aud if isinstance(aud, list) else [aud]
                if self._audience not in auds:
                    raise AudienceMismatchError("aud %r missing %r" % (aud, self._audience))

            exp = payload.get("exp")
            if isinstance(exp, bool) or not isinstance(exp, int):
                raise ExpiredTokenError("exp must be an int seq")
            if exp <= seq:
                raise ExpiredTokenError("expired at seq %d (now %d)" % (exp, seq))

            nbf = payload.get("nbf")
            if nbf is not None:
                if isinstance(nbf, bool) or not isinstance(nbf, int):
                    raise NotYetValidError("nbf must be an int seq")
                if nbf > seq:
                    raise NotYetValidError("not valid until seq %d (now %d)" % (nbf, seq))

            jti = payload.get("jti")
            if isinstance(jti, str) and jti in self._revoked:
                raise RevokedTokenError("jti %r revoked" % jti)

            return VerifiedClaims(
                claims=dict(payload),
                token_digest=_digest(token.encode("ascii")),
                seq=seq,
            )

    def decode(self, token: str) -> DecodedToken:
        """Parse header/payload WITHOUT verifying the signature.

        Inspection only - the returned claims are *unverified*.
        """
        header, payload, _sig, _inp = self._parse(token)
        return DecodedToken(header=header, payload=payload)

    def revoke(self, jti: str, seq: int) -> None:
        """Revoke a token by its jti; future verify() calls fail."""
        with self._lock:
            seq = _check_seq(seq)
            if not isinstance(jti, str) or not jti:
                raise JWTError("jti must be a non-empty str")
            self._revoked[jti] = seq

    def is_revoked(self, jti: str) -> bool:
        with self._lock:
            return jti in self._revoked

    @property
    def issuer(self) -> str:
        return self._issuer

    @property
    def audience(self) -> Optional[str]:
        return self._audience


_AUDIT_KINDS = ("issued", "verified", "rejected")


def jwt_handler_audit_event(
    kind: str,
    seq: int,
    detail: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Shape an audit.ndjson/1 record for JWT operations (digests only)."""
    if kind not in _AUDIT_KINDS:
        raise JWTError("unknown audit kind: %r" % kind)
    seq = _check_seq(seq)
    record: Dict[str, Any] = {
        "schema": AUDIT_SCHEMA,
        "module": "jwt-handler",
        "module_version": JWT_HANDLER_VERSION,
        "kind": kind,
        "seq": seq,
    }
    if detail is not None:
        if not isinstance(detail, Mapping):
            raise JWTError("detail must be a mapping")
        record["detail"] = dict(detail)
    return record


def main() -> None:
    h = JWTHandler(secret=b"0" * 32, issuer="northstar", audience="agents")
    signed = h.sign({"sub": "agent-1", "aud": "agents"}, seq=10, ttl_seqs=100)
    assert h.verify(signed.token, seq=11).claims["sub"] == "agent-1"
    assert h.decode(signed.token).payload["iss"] == "northstar"
    try:
        h.verify(signed.token, seq=200)
    except ExpiredTokenError:
        pass
    else:
        raise AssertionError("expiry not enforced")
    h.revoke(signed.jti, seq=12)
    try:
        h.verify(signed.token, seq=13)
    except RevokedTokenError:
        pass
    else:
        raise AssertionError("revocation not enforced")
    print("jwt-handler OK: sign, verify, decode, expiry, revocation")


if __name__ == "__main__":
    main()
