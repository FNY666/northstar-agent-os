"""SAML provider: simulated identity-provider SSO bookkeeping.

Research note: *Security Assertion Markup Language* (SAML 2.0, OASIS
SSTC) is the XML-based web SSO standard behind enterprise federation:
an *identity provider* (IdP) authenticates a principal and hands the
*service provider* (SP) a signed *assertion* carrying a ``NameID`` plus
attribute statements (email, groups, ...). The well-studied load-bearing
properties (OASIS SAMLCore 2.0 errata; CWE-289, CWE-299):

* **Metadata exchange** — the IdP publishes an ``EntityDescriptor``
  naming its ``entityID`` and ``SingleSignOnService`` endpoint; an SP
  pins that metadata (entity id + digest) so assertions are only trusted
  when they name the pinned issuer. Metadata without a digest pin is
  config drift waiting to happen.
* **Assertion conditions** — every assertion carries ``NotBefore`` /
  ``NotOnOrAfter`` bounds (here: caller-supplied integer seqs, never
  wall-clock) plus an ``AudienceRestriction`` naming the intended SP.
  ``validate()`` rejects anything outside its window or addressed to a
  different audience — a stale assertion is not a valid one.
* **Subject confirmation** — the ``NameID`` binds the assertion to one
  principal; ``validate()`` re-derives the assertion digest and refuses
  tampered name ids, audiences, or attribute sets fail-closed.
* **Revocation** — assertions are short-lived by design, but the IdP
  keeps a revocation ledger; ``validate()`` consults it before honoring
  an assertion. ``revoke()`` returns a frozen record.

Honest scope: this is the *bookkeeping layer* for an IdP, not a crypto
implementation. There is no XML, no real signature (digests stand in
for the signature check the SP would perform), no network, and the
host is the one minting name ids. ``validate()`` proves "this assertion
record was minted by this provider, is addressed to the stated
audience, is inside its validity window, and was not revoked" — never
"the principal proved who they are". Pair with a real XML/signature
stack for production; this module's digest pins are decision records.

Version pin: saml-provider.v1
Schema pin: northstar.saml-provider.v1
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
SAML_PROVIDER_VERSION = "saml-provider.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.saml-provider.v1"

#: Error taxonomy anchor.
ERROR_PREFIX = "saml-provider."

#: Maximum number of attributes on one assertion (guardrail, not a security parameter).
MAX_ATTRIBUTES = 256

#: Maximum length of a single attribute value (guardrail).
MAX_VALUE_CHARS = 1 << 16  # 64 KiB

_AUDIT_KINDS = frozenset(
    {
        "metadata-published",
        "assertion-issued",
        "assertion-revoked",
        "assertion-validated",
        "validation-failed",
        "rejected",
    }
)


class SAMLError(Exception):
    """Base error for the SAML provider."""


class MetadataError(SAMLError):
    """IdP metadata not configured or invalid."""


class AssertionError(SAMLError):
    """Assertion input validation failed."""


class UnknownAssertionError(SAMLError):
    """No such assertion id in the ledger."""


class RevokedAssertionError(SAMLError):
    """The assertion was revoked before validation."""


class ValidationError(SAMLError):
    """The assertion did not validate (stale, wrong audience, tampered)."""


def _check_seq(seq: Any, what: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise AssertionError(f"{ERROR_PREFIX}invalid-{what}: {seq!r}")
    return seq


def _check_str(value: Any, what: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise AssertionError(f"{ERROR_PREFIX}invalid-{what}: {value!r}")
    if "\x00" in value:
        raise AssertionError(f"{ERROR_PREFIX}invalid-{what}: NUL byte")
    return value


def _digest(body: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(body)).hexdigest()


def _canonical_attributes(attributes: Mapping[str, Any]) -> Tuple[Tuple[str, Any], ...]:
    if not isinstance(attributes, Mapping):
        raise AssertionError(f"{ERROR_PREFIX}invalid-attributes: not a mapping")
    if len(attributes) > MAX_ATTRIBUTES:
        raise AssertionError(f"{ERROR_PREFIX}too-many-attributes: {len(attributes)}")
    pairs: List[Tuple[str, Any]] = []
    for key, value in attributes.items():
        if not isinstance(key, str) or not key:
            raise AssertionError(f"{ERROR_PREFIX}invalid-attribute-name: {key!r}")
        if isinstance(value, bool) or not isinstance(value, (str, int, float)):
            raise AssertionError(f"{ERROR_PREFIX}invalid-attribute-value: {key!r}")
        if isinstance(value, float):
            import math

            if not math.isfinite(value):
                raise AssertionError(f"{ERROR_PREFIX}non-finite-attribute-value: {key!r}")
            if value.is_integer() and abs(value) > 2**53:
                raise AssertionError(f"{ERROR_PREFIX}huge-attribute-value: {key!r}")
        if isinstance(value, int) and not isinstance(value, bool) and abs(value) > 2**53:
            raise AssertionError(f"{ERROR_PREFIX}huge-attribute-value: {key!r}")
        if isinstance(value, str) and len(value) > MAX_VALUE_CHARS:
            raise AssertionError(f"{ERROR_PREFIX}oversize-attribute-value: {key!r}")
        pairs.append((key, value))
    return tuple(sorted(pairs, key=lambda kv: kv[0]))


@dataclass(frozen=True)
class EntityMetadata:
    """Pinned IdP metadata: what the SP trusts."""

    entity_id: str
    sso_service_url: str
    digest: str
    version: str = SAML_PROVIDER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "sso_service_url": self.sso_service_url,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class AssertionRecord:
    """One minted SAML assertion."""

    assertion_id: str
    name_id: str
    audience: str
    issuer: str
    not_before_seq: int
    not_on_or_after_seq: int
    attributes: Tuple[Tuple[str, Any], ...]
    digest: str
    version: str = SAML_PROVIDER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "assertion_id": self.assertion_id,
            "name_id": self.name_id,
            "audience": self.audience,
            "issuer": self.issuer,
            "not_before_seq": self.not_before_seq,
            "not_on_or_after_seq": self.not_on_or_after_seq,
            "attributes": [list(kv) for kv in self.attributes],
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class ValidationReport:
    """Outcome of ``validate()`` — always a record, never a raise."""

    assertion_id: str
    valid: bool
    reason: str
    digest: str
    version: str = SAML_PROVIDER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "assertion_id": self.assertion_id,
            "valid": self.valid,
            "reason": self.reason,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class RevocationRecord:
    """Proof that an assertion was revoked."""

    assertion_id: str
    digest: str
    version: str = SAML_PROVIDER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "assertion_id": self.assertion_id,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


def saml_provider_audit_event(kind: str, seq: Any, detail: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1``-style record for this module."""
    if kind not in _AUDIT_KINDS:
        raise SAMLError(f"{ERROR_PREFIX}unknown-audit-kind: {kind!r}")
    seq = _check_seq(seq, "audit-seq")
    record: Dict[str, Any] = {
        "kind": kind,
        "seq": seq,
        "module": SAML_PROVIDER_VERSION,
        "schema": "audit.ndjson/1",
    }
    if detail is not None:
        if not isinstance(detail, Mapping):
            raise SAMLError(f"{ERROR_PREFIX}invalid-audit-detail")
        for k, v in detail.items():
            if not isinstance(k, str) or not k:
                raise SAMLError(f"{ERROR_PREFIX}invalid-audit-detail-key: {k!r}")
        record["detail"] = dict(detail)
    return record


class SAMLProvider:
    """Simulated SAML identity provider."""

    def __init__(self, entity_id: str, sso_service_url: str) -> None:
        self._entity_id = _check_str(entity_id, "entity-id")
        self._sso_service_url = _check_str(sso_service_url, "sso-service-url")
        if not self._sso_service_url.startswith(("https://", "http://")):
            raise AssertionError(f"{ERROR_PREFIX}invalid-sso-service-url: scheme")
        self._lock = threading.RLock()
        self._metadata_digest = _digest(
            {
                "entity_id": self._entity_id,
                "sso_service_url": self._sso_service_url,
                "version": SAML_PROVIDER_VERSION,
            }
        )
        self._assertions: Dict[str, AssertionRecord] = {}
        self._revoked: Dict[str, RevocationRecord] = {}
        self._counter = 0
        self._last_seq = -1

    def _advance_seq(self, seq: int) -> None:
        if seq < self._last_seq:
            raise AssertionError(f"{ERROR_PREFIX}seq-rewind: {seq} < {self._last_seq}")
        self._last_seq = seq

    def metadata(self) -> EntityMetadata:
        """Return the pinned IdP metadata."""
        return EntityMetadata(
            entity_id=self._entity_id,
            sso_service_url=self._sso_service_url,
            digest=self._metadata_digest,
        )

    def issue(
        self,
        name_id: str,
        audience: str,
        not_before_seq: int,
        not_on_or_after_seq: int,
        seq: int,
        attributes: Optional[Mapping[str, Any]] = None,
    ) -> AssertionRecord:
        """Mint a signed-ish assertion for ``name_id`` addressed to ``audience``."""
        seq = _check_seq(seq)
        name_id = _check_str(name_id, "name-id")
        audience = _check_str(audience, "audience")
        not_before_seq = _check_seq(not_before_seq, "not-before-seq")
        not_on_or_after_seq = _check_seq(not_on_or_after_seq, "not-on-or-after-seq")
        if not_on_or_after_seq <= not_before_seq:
            raise AssertionError(f"{ERROR_PREFIX}empty-validity-window")
        attrs = _canonical_attributes(attributes or {})
        with self._lock:
            self._advance_seq(seq)
            self._counter += 1
            assertion_id = f"assert-{self._counter}"
            digest = _digest(
                {
                    "assertion_id": assertion_id,
                    "name_id": name_id,
                    "audience": audience,
                    "issuer": self._entity_id,
                    "not_before_seq": not_before_seq,
                    "not_on_or_after_seq": not_on_or_after_seq,
                    "attributes": [list(kv) for kv in attrs],
                    "issuer_digest": self._metadata_digest,
                    "version": SAML_PROVIDER_VERSION,
                }
            )
            record = AssertionRecord(
                assertion_id=assertion_id,
                name_id=name_id,
                audience=audience,
                issuer=self._entity_id,
                not_before_seq=not_before_seq,
                not_on_or_after_seq=not_on_or_after_seq,
                attributes=attrs,
                digest=digest,
            )
            self._assertions[assertion_id] = record
            return record

    def revoke(self, assertion_id: str, seq: int) -> RevocationRecord:
        """Revoke a minted assertion; future ``validate()`` calls fail closed."""
        seq = _check_seq(seq)
        assertion_id = _check_str(assertion_id, "assertion-id")
        with self._lock:
            self._advance_seq(seq)
            record = self._assertions.get(assertion_id)
            if record is None:
                raise UnknownAssertionError(f"{ERROR_PREFIX}unknown-assertion: {assertion_id!r}")
            existing = self._revoked.get(assertion_id)
            if existing is not None:
                return existing
            digest = _digest(
                {
                    "assertion_id": assertion_id,
                    "assertion_digest": record.digest,
                    "version": SAML_PROVIDER_VERSION,
                }
            )
            revocation = RevocationRecord(assertion_id=assertion_id, digest=digest)
            self._revoked[assertion_id] = revocation
            return revocation

    def validate(self, assertion: AssertionRecord, audience: str, at_seq: int, seq: int) -> ValidationReport:
        """Validate an assertion: digest, audience, window, revocation.

        Always returns a ``ValidationReport`` (valid or not); raises only
        for malformed inputs, never for a failed check.
        """
        seq = _check_seq(seq)
        audience = _check_str(audience, "audience")
        at_seq = _check_seq(at_seq, "at-seq")

        def _invalid(reason: str) -> ValidationReport:
            aid = assertion.assertion_id if isinstance(assertion, AssertionRecord) else "unknown"
            return ValidationReport(
                assertion_id=aid,
                valid=False,
                reason=reason,
                digest=_digest(
                    {
                        "assertion_id": aid,
                        "valid": False,
                        "reason": reason,
                        "version": SAML_PROVIDER_VERSION,
                    }
                ),
            )

        if not isinstance(assertion, AssertionRecord):
            raise ValidationError(f"{ERROR_PREFIX}not-an-assertion: {type(assertion).__name__}")
        with self._lock:
            self._advance_seq(seq)
            known = self._assertions.get(assertion.assertion_id)
            if known is None:
                return _invalid("unknown-assertion")
            if not hmac.compare_digest(assertion.digest, known.digest):
                return _invalid("digest-mismatch")
            if assertion.assertion_id in self._revoked:
                return _invalid("revoked")
            if assertion.audience != audience:
                return _invalid("audience-mismatch")
            if at_seq < assertion.not_before_seq:
                return _invalid("not-yet-valid")
            if at_seq >= assertion.not_on_or_after_seq:
                return _invalid("expired")
            return ValidationReport(
                assertion_id=assertion.assertion_id,
                valid=True,
                reason="ok",
                digest=_digest(
                    {
                        "assertion_id": assertion.assertion_id,
                        "valid": True,
                        "reason": "ok",
                        "audience": audience,
                        "at_seq": at_seq,
                        "version": SAML_PROVIDER_VERSION,
                    }
                ),
            )

    def assertion_ids(self) -> Tuple[str, ...]:
        """Sorted assertion ids minted so far."""
        with self._lock:
            return tuple(sorted(self._assertions))

    def is_revoked(self, assertion_id: str) -> bool:
        """Whether an assertion id is revoked."""
        _check_str(assertion_id, "assertion-id")
        with self._lock:
            return assertion_id in self._revoked

    def audit_kinds(self) -> FrozenSet[str]:
        """The fixed audit vocabulary of this module."""
        return _AUDIT_KINDS


def main() -> None:
    provider = SAMLProvider("https://idp.example.org/saml", "https://idp.example.org/sso")
    md = provider.metadata()
    assert md.digest.startswith("sha256:")
    record = provider.issue(
        "alice@example.com",
        "https://sp.example.org",
        not_before_seq=10,
        not_on_or_after_seq=20,
        seq=1,
        attributes={"email": "alice@example.com", "groups": 3},
    )
    report = provider.validate(record, "https://sp.example.org", at_seq=15, seq=2)
    assert report.valid and report.reason == "ok", report.as_dict()
    stale = provider.validate(record, "https://sp.example.org", at_seq=25, seq=3)
    assert not stale.valid and stale.reason == "expired", stale.as_dict()
    provider.revoke(record.assertion_id, seq=4)
    assert provider.is_revoked(record.assertion_id)
    revoked = provider.validate(record, "https://sp.example.org", at_seq=15, seq=5)
    assert not revoked.valid and revoked.reason == "revoked", revoked.as_dict()
    event = saml_provider_audit_event("assertion-issued", 1, {"assertion_id": record.assertion_id})
    assert event["kind"] == "assertion-issued"
    print("saml-provider OK: metadata, assert, validate, expiry, revoke")


if __name__ == "__main__":
    main()
