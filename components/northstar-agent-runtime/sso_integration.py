"""SSO integration (P0): provider registration, assertion validation, JIT provisioning.

Interface:
    SSOIntegration.provider(provider_id, provider_type, seq, issuer=, entity_id=,
                             acs_url=, client_secret=) -> ProviderRecord
    SSOIntegration.login(provider_id, assertion, seq) -> LoginDecision (verdict is data)
    SSOIntegration.jit(provider_id, login_decision, seq) -> ProvisionRecord

Simulated identity layer: this module books *reported* SSO events and
verifies the shape of host-presented assertions. It performs no network
I/O, no XML/HTML parsing, and no real IdP wire validation.

House style: frozen dataclasses, caller-supplied strictly increasing int
``seq`` (no wall-clock), RLock-guarded, fail-closed, stdlib-only with a
``canonical_json`` try/except fallback, ``sha256:`` digest pins, audit
events as ``audit.ndjson/1`` JSONL records.

Security notes
--------------
- Secrets (client_secret, assertion values) are never stored raw: the
  module books domain-separated HMAC verifiers only, and raw assertion
  text is banned from the audit boundary (ids + digests + verdicts only).
- ``login`` verdicts are data, never exceptions: a failed assertion
  returns ``LoginDecision(valid=False, reason=...)``. Unknown providers
  and malformed inputs raise fail-closed.
- JIT is idempotent and deterministic: the same (provider, sub) always
  binds to the same subject id, so re-login never forks identities.
  Rebinding a subject to a *different* provider/sub is refused.
- Subject ids are derived with a constructor seed: hosts that need
  stable subjects across restarts pass ``seed=`` explicitly.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
SSO_INTEGRATION_VERSION = "sso-integration.v1"

#: Schema pin carried by records and audit events.
SCHEMA_PIN = "northstar.sso-integration.v1"

#: Schema pin for audit.ndjson records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned provider-type vocabulary (SAML/OIDC). Drift is detectable via digest.
PROVIDER_TYPES = ("oidc", "saml", "oauth2")

#: Reasons a login can be invalid (as data).
_INVALID_REASONS = (
    "expired",
    "wrong-issuer",
    "wrong-audience",
    "missing-sub",
    "bad-signature",
    "replayed-nonce",
)

_PROVIDER_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?$")
_URI_RE = re.compile(r"^[a-z][a-z0-9+.-]{1,31}://\S{1,2000}$")
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,253}$")


def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore
    import json

    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _digest(domain: bytes, payload: Any) -> str:
    return "sha256:" + hmac.new(domain, _canonical(payload),
                                hashlib.sha256).hexdigest()


def _mask_secret(verifier_seed: bytes, secret: str) -> str:
    """Domain-separated HMAC verifier for a secret (never the raw secret)."""
    return "sha256:" + hmac.new(verifier_seed, secret.encode("utf-8"),
                                hashlib.sha256).hexdigest()


class SSOError(Exception):
    """Base error for the SSO integration."""


class UnknownProviderError(SSOError):
    """Raised when a provider_id is not registered."""


class DuplicateProviderError(SSOError):
    """Raised when a provider_id is already registered."""


class BadProviderError(SSOError):
    """Raised for malformed provider registration inputs."""


class BadAssertionError(SSOError):
    """Raised for structurally malformed assertions (wrong types, etc.)."""


class UnknownSubjectError(SSOError):
    """Raised when JIT-binding a subject that is not provisioned."""


class BindingConflictError(SSOError):
    """Raised when rebinding a subject id to a different (provider, sub)."""


class SeqOrderError(SSOError):
    """Raised when a mutation seq does not strictly increase."""


@dataclass(frozen=True)
class ProviderRecord:
    """A registered IdP: type, issuer, and digest-pinned metadata."""

    provider_id: str
    provider_type: str
    issuer: str
    entity_id: str
    registered_seq: int
    acs_url: str = ""
    require_signed_assertions: bool = True
    digest: str = ""


@dataclass(frozen=True)
class Assertion:
    """A host-presented identity assertion (simulated IdP output)."""

    sub: str
    issuer: str
    audience: str
    exp_seq: int
    issued_seq: int
    attributes: Mapping[str, str] = field(default_factory=dict)
    signature_verifier: str = ""
    nonce: str = ""


@dataclass(frozen=True)
class LoginDecision:
    """Outcome of validating one assertion: verdict is data, never raises."""

    provider_id: str
    valid: bool
    sub: str = ""
    subject_hint: str = ""
    reason: str = ""
    verified_claims: Mapping[str, str] = field(default_factory=dict)
    login_seq: int = 0
    digest: str = ""


@dataclass(frozen=True)
class ProvisionRecord:
    """A JIT-provisioned subject bound to exactly one (provider, sub)."""

    subject_id: str
    provider_id: str
    sub: str
    email: str = ""
    display_name: str = ""
    groups: Tuple[str, ...] = ()
    provisioned_seq: int = 0
    last_login_seq: int = 0
    digest: str = ""


class SSOIntegration:
    """Single-host SSO provider registry with simulated assertion login."""

    def __init__(self, seed: bytes = b"") -> None:
        self._seed = seed
        self._providers: Dict[str, ProviderRecord] = {}
        self._subjects: Dict[str, ProvisionRecord] = {}
        self._seen_nonces: Dict[str, Tuple[str, int]] = {}
        self._audit: List[Dict[str, Any]] = []
        self._last_seq = -1
        self._lock = threading.RLock()

    # -- internals -------------------------------------------------------

    def _check_seq(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError(f"seq must be int, got {type(seq).__name__}")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase: {seq} <= {self._last_seq}")
        self._last_seq = seq

    def _record(self, seq: int, kind: str,
                payload: Mapping[str, Any]) -> None:
        self._audit.append({
            "seq": seq,
            "kind": kind,
            "payload": dict(payload),
            "schema": AUDIT_SCHEMA,
            "module": SSO_INTEGRATION_VERSION,
        })

    def _digest(self, payload: Any) -> str:
        return _digest(self._seed or b"sso-integration", payload)

    def _provider(self, provider_id: str) -> ProviderRecord:
        try:
            return self._providers[provider_id]
        except KeyError:
            raise UnknownProviderError(
                f"unknown provider: {provider_id}") from None

    # -- provider registry -----------------------------------------------

    def provider(self, provider_id: str, provider_type: str, seq: int,
                 issuer: str = "", entity_id: str = "",
                 acs_url: str = "", client_secret: Optional[str] = None,
                 require_signed_assertions: bool = True) -> ProviderRecord:
        """Register an IdP configuration. Secrets are never stored raw."""
        self._check_seq(seq)
        try:
            if not _PROVIDER_ID_RE.match(provider_id or ""):
                raise BadProviderError(
                    f"bad provider_id: {provider_id!r}")
            if provider_type not in PROVIDER_TYPES:
                raise BadProviderError(
                    f"unknown provider_type: {provider_type!r}")
            if provider_id in self._providers:
                raise DuplicateProviderError(
                    f"duplicate provider_id: {provider_id}")
            issuer = (issuer or "").strip()
            if not issuer or len(issuer) > 2000:
                raise BadProviderError("issuer must be a non-empty string")
            entity_id = (entity_id or "").strip()
            if entity_id and len(entity_id) > 2000:
                raise BadProviderError("entity_id too long")
            if not isinstance(acs_url, str) or len(acs_url) > 2000:
                raise BadProviderError("acs_url must be a string")
            if acs_url and not _URI_RE.match(acs_url):
                raise BadProviderError(f"bad acs_url: {acs_url!r}")
            if client_secret is not None and not isinstance(client_secret,
                                                            str):
                raise BadProviderError("client_secret must be a string")
            if not isinstance(require_signed_assertions, bool):
                raise BadProviderError(
                    "require_signed_assertions must be bool")
            digest = self._digest(
                ("provider", provider_id, provider_type, issuer,
                 entity_id, acs_url, str(seq)))
            record = ProviderRecord(
                provider_id=provider_id,
                provider_type=provider_type,
                issuer=issuer,
                entity_id=entity_id or issuer,
                registered_seq=seq,
                acs_url=acs_url,
                require_signed_assertions=require_signed_assertions,
                digest=digest,
            )
            self._providers[provider_id] = record
            payload: Dict[str, Any] = {
                "provider_id": provider_id,
                "provider_type": provider_type,
                "issuer": issuer,
                "digest": digest,
            }
            if client_secret is not None:
                payload["secret_verifier"] = _mask_secret(
                    self._seed or b"sso-integration", client_secret)
            self._record(seq, "provider-registered", payload)
            return record
        except Exception:
            self._record(seq, "rejected", {
                "op": "provider", "provider_id": provider_id,
                "error": "bad-provider",
            })
            raise

    # -- login -----------------------------------------------------------

    def login(self, provider_id: str, assertion: Assertion,
              seq: int) -> LoginDecision:
        """Validate a host-presented assertion. Verdict is data, never raises.

        The ``seq`` is a logical clock: ``exp_seq`` bounds it. ``seq``
        consumption follows the mutation discipline (failed validations
        consume their seq) because every login attempt is booked.
        """
        self._check_seq(seq)
        try:
            prov = self._provider(provider_id)
            if not isinstance(assertion, Assertion):
                raise BadAssertionError("assertion must be an Assertion")
            reason = self._validate(prov, assertion, seq)
            claims = self._claims(prov, assertion)
            hint = ""
            if reason == "":
                hint = self._digest(
                    ("subject", provider_id, assertion.sub))[:21]
                self._seen_nonces[assertion.nonce] = (provider_id, seq)
            digest = self._digest(
                ("login", provider_id, assertion.sub, assertion.issuer,
                 assertion.audience, str(assertion.exp_seq),
                 str(assertion.issued_seq), str(seq)))
            decision = LoginDecision(
                provider_id=provider_id,
                valid=reason == "",
                sub=assertion.sub if reason == "" else "",
                subject_hint=hint,
                reason=reason,
                verified_claims=claims,
                login_seq=seq,
                digest=digest,
            )
            self._record(seq, "login", {
                "provider_id": provider_id,
                "valid": decision.valid,
                "reason": reason or "ok",
                "digest": digest,
            })
            return decision
        except (UnknownProviderError, BadAssertionError):
            self._record(seq, "rejected", {
                "op": "login", "provider_id": provider_id,
                "error": "bad-login-input",
            })
            raise

    def _validate(self, prov: ProviderRecord, a: Assertion,
                  seq: int) -> str:
        """Return the invalid reason, or '' for valid."""
        if not isinstance(a.sub, str) or not a.sub:
            return "missing-sub"
        if not isinstance(a.issuer, str) or not a.issuer:
            return "wrong-issuer"
        if a.issuer != prov.issuer:
            return "wrong-issuer"
        if not isinstance(a.audience, str) or not a.audience:
            return "wrong-audience"
        if a.audience != prov.entity_id:
            return "wrong-audience"
        for name in ("exp_seq", "issued_seq"):
            v = getattr(a, name)
            if isinstance(v, bool) or not isinstance(v, int):
                return "expired"
        if a.exp_seq <= a.issued_seq:
            return "expired"
        if a.exp_seq <= seq:
            return "expired"
        if prov.require_signed_assertions and not a.signature_verifier:
            return "bad-signature"
        if not isinstance(a.nonce, str) or not a.nonce:
            return "replayed-nonce"
        if a.nonce in self._seen_nonces:
            return "replayed-nonce"
        if not isinstance(a.attributes, Mapping):
            return "missing-sub"
        return ""

    def _claims(self, prov: ProviderRecord,
                a: Assertion) -> Dict[str, str]:
        claims: Dict[str, str] = {}
        for k, v in (a.attributes or {}).items():
            if isinstance(k, str) and isinstance(v, str) and len(k) <= 128:
                claims[k] = v[:2048]
        return claims

    # -- just-in-time provisioning ---------------------------------------

    def jit(self, provider_id: str, decision: LoginDecision,
            seq: int) -> ProvisionRecord:
        """Provision (or re-link) a subject from a valid login decision.

        Idempotent: the same (provider, sub) always returns the same
        subject id with ``last_login_seq`` advanced. Rebinding a subject
        id to a different (provider, sub) is refused fail-closed.
        """
        self._check_seq(seq)
        try:
            prov = self._provider(provider_id)
            if not isinstance(decision, LoginDecision):
                raise BadAssertionError("decision must be a LoginDecision")
            if decision.provider_id != provider_id:
                raise BadAssertionError("decision is for another provider")
            if not decision.valid:
                raise BadAssertionError(
                    f"cannot JIT an invalid login: {decision.reason}")
            sub = decision.sub.strip()
            if not sub:
                raise BadAssertionError("decision carries no subject")
            subject_id = self._subject_id(provider_id, sub)
            email = decision.verified_claims.get("email", "")
            if not _EMAIL_RE.match(email or ""):
                email = ""
            name = decision.verified_claims.get("name", "")[:256]
            groups = tuple(sorted(
                g[:128] for g in decision.verified_claims.get(
                    "groups", "").split(",") if g.strip()))
            existing = self._subjects.get(subject_id)
            if existing is not None:
                if existing.sub != sub or \
                        existing.provider_id != provider_id:
                    raise BindingConflictError(
                        f"subject {subject_id} already bound elsewhere")
                record = ProvisionRecord(
                    subject_id=existing.subject_id,
                    provider_id=existing.provider_id,
                    sub=existing.sub,
                    email=email or existing.email,
                    display_name=name or existing.display_name,
                    groups=groups or existing.groups,
                    provisioned_seq=existing.provisioned_seq,
                    last_login_seq=seq,
                    digest=self._digest(
                        ("jit", subject_id, provider_id, sub, str(seq))),
                )
                op = "jit-relinked"
            else:
                record = ProvisionRecord(
                    subject_id=subject_id,
                    provider_id=provider_id,
                    sub=sub,
                    email=email,
                    display_name=name,
                    groups=groups,
                    provisioned_seq=seq,
                    last_login_seq=seq,
                    digest=self._digest(
                        ("jit", subject_id, provider_id, sub, str(seq))),
                )
                op = "jit-provisioned"
            self._subjects[subject_id] = record
            self._record(seq, op, {
                "subject_id": subject_id,
                "provider_id": provider_id,
                "digest": record.digest,
            })
            return record
        except (UnknownProviderError, BadAssertionError,
                BindingConflictError):
            self._record(seq, "rejected", {
                "op": "jit", "provider_id": provider_id,
                "error": "bad-jit-input",
            })
            raise

    def _subject_id(self, provider_id: str, sub: str) -> str:
        raw = self._digest(("subject", provider_id, sub))
        return "usr_" + raw[7:19]

    # -- views -----------------------------------------------------------

    def providers(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._providers))

    def provider_record(self, provider_id: str) -> ProviderRecord:
        with self._lock:
            return self._provider(provider_id)

    def subject(self, subject_id: str) -> ProvisionRecord:
        with self._lock:
            try:
                return self._subjects[subject_id]
            except KeyError:
                raise UnknownSubjectError(
                    f"unknown subject: {subject_id}") from None

    def subject_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._subjects))

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)

    def as_dict(self) -> Dict[str, Any]:
        """Ledger snapshot. Secrets/assertions never appear here."""
        return {
            "version": SSO_INTEGRATION_VERSION,
            "schema": SCHEMA_PIN,
            "last_seq": self._last_seq,
            "providers": [
                {
                    "provider_id": p.provider_id,
                    "provider_type": p.provider_type,
                    "issuer": p.issuer,
                    "entity_id": p.entity_id,
                    "registered_seq": p.registered_seq,
                    "digest": p.digest,
                }
                for p in sorted(self._providers.values(),
                                key=lambda p: p.provider_id)
            ],
            "subjects": [
                {
                    "subject_id": s.subject_id,
                    "provider_id": s.provider_id,
                    "provisioned_seq": s.provisioned_seq,
                    "digest": s.digest,
                }
                for s in sorted(self._subjects.values(),
                                key=lambda s: s.subject_id)
            ],
        }


def sso_integration_audit_event(seq: int, kind: str,
                                payload: Mapping[str, Any]
                                ) -> Dict[str, Any]:
    """Build a canonical audit event dict for external audit pipelines."""
    allowed = {"provider-registered", "login", "jit-provisioned",
               "jit-relinked", "rejected"}
    if kind not in allowed:
        raise ValueError(f"bad audit kind: {kind!r}")
    banned = {"assertion", "client_secret", "secret", "attributes",
              "sub", "email", "claims", "token", "password"}
    detail = {k: v for k, v in payload.items() if k not in banned}
    return {
        "seq": seq,
        "kind": kind,
        "payload": detail,
        "schema": AUDIT_SCHEMA,
        "module": SSO_INTEGRATION_VERSION,
    }


def main() -> None:
    sso = SSOIntegration(seed=b"sso-selfcheck")
    prov = sso.provider("corp-okta", "oidc", 1,
                        issuer="https://corp.example.okta.com",
                        entity_id="https://corp.example.okta.com",
                        client_secret="topsecret")
    assert prov.provider_id == "corp-okta"
    assert "client_secret" not in repr(prov) and prov.digest
    a = Assertion(sub="alice", issuer="https://corp.example.okta.com",
                  audience="https://corp.example.okta.com",
                  exp_seq=100, issued_seq=2, nonce="n1",
                  signature_verifier="sig1",
                  attributes={"sub": "alice", "email": "a@x.io",
                              "name": "Alice", "groups": "eng,sec"})
    d = sso.login("corp-okta", a, 3)
    assert d.valid and d.reason == "" and d.digest
    rec = sso.jit("corp-okta", d, 4)
    assert rec.subject_id.startswith("usr_") and rec.email == "a@x.io"
    rec2 = sso.jit("corp-okta", sso.login("corp-okta",
                  Assertion(sub="alice",
                            issuer="https://corp.example.okta.com",
                            audience="https://corp.example.okta.com",
                            exp_seq=100, issued_seq=2, nonce="n2",
                            signature_verifier="sig2",
                            attributes={"sub": "alice"}), 5), 6)
    assert rec2.subject_id == rec.subject_id and \
        rec2.provisioned_seq == rec.provisioned_seq
    ev = sso_integration_audit_event(1, "login", {"provider_id": "x"})
    assert ev["schema"] == AUDIT_SCHEMA
    print("sso-integration OK: provider, login, jit, pins, audit")


if __name__ == "__main__":
    main()
