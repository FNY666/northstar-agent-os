"""Organization manager: multi-tenant orgs, domain claims, and SSO bindings.

Research note: multi-tenant SaaS converges on one ownership hierarchy —
``organization -> domains -> identity provider bindings``. Okta, Auth0,
GitHub Organizations, and Google Workspace all bind SSO *to an org* and
gate it on *verified domain ownership*: you may not attach a corporate
IdP to an org until the org proves it controls the email domain the IdP
asserts. That ordering is not bureaucracy, it is the anti-takeover
invariant — without it, anyone who creates an org first can capture
another company's SSO logins.

Interface shape:

* **create** — mint an org record: unique ``org_id`` (``org_`` + digest),
  human ``name``, URL-safe ``slug``. Slugs are globally unique; names are
  not (two "Acme" tenants are legal, their slugs differ).
* **domain** — claim a DNS domain for an org. Domains are globally unique:
  one domain belongs to at most one org, ever (no transfer — a transfer is
  delete + re-claim, which keeps the audit trail honest). Claims start
  *unverified*; ``verify_domain`` flips the flag only after an external
  proof step the host performs (DNS TXT / file upload) and reports back.
* **sso** — bind an SSO provider config (``oidc`` / ``saml`` /
  ``oauth2``) to an org. Fail-closed: an org with no *verified* domain
  cannot bind SSO. Re-binding the same org replaces the config (new seq,
  old config retained in audit only).

Lifecycle: ``active -> suspended -> active``. A suspended org is
read-only for mutations: no new domains, no domain verification, no SSO
changes. Suspension is terminal-ish but reversible by design — a billing
lapse should not destroy the tenant record.

All mutations take caller-supplied logical ``seq`` (no wall-clock): seqs
must strictly increase per manager (``SeqOrderError``), so the ledger
order is total and replay-exact. A clock that moves backwards cannot
resurrect a revoked claim or replay an old SSO binding.

Fail-closed rules (load-bearing):

* ``slug`` is globally unique: re-creating an existing slug raises
  ``DuplicateOrgError``, even after suspension.
* ``domain`` is globally unique: claiming a claimed domain raises
  ``DuplicateDomainError``, even across orgs; domains are never moved.
* SSO binding requires at least one verified domain on the org —
  ``SSOPreconditionError`` otherwise. This is the anti-takeover rule.
* Mutations on a suspended org raise ``SuspendedOrgError``.
* Mutation seqs must strictly increase per manager (``SeqOrderError``).
* Unknown org ids raise ``UnknownOrgError``; malformed ids are rejected
  as data (``ValueError``), never silently normalized.
* SSO configs may carry secrets (``client_secret``); secrets are
  HMAC-masked in ``as_dict()`` and never appear in digests or audit
  payloads.

Honest scope: this books *reported* org/domain/SSO lifecycle events. It
cannot prove DNS ownership, cannot observe the IdP wire, and the domain
verification flag is only as honest as the host that reports the proof.
Production deployments must perform real DNS/HTTP proof-of-control and
store IdP secrets in a real secret manager. With an explicit ``seed=``
the module is fully deterministic for tests and audit replay; the
default salt comes from ``secrets.token_bytes``.

Version pin: org-manager.v1
Schema pin: northstar.org-manager.v1
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

ORG_MANAGER_VERSION = "org-manager.v1"
SCHEMA_PIN = "northstar.org-manager.v1"

_ORG_ID_PREFIX = "org_"
_ID_HEX_LEN = 16
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,}$"
)
_SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
_SSO_PROVIDERS = ("oidc", "saml", "oauth2")


class OrgError(Exception):
    """Base error for the org manager."""


class DuplicateOrgError(OrgError):
    """Raised when a slug is already taken."""


class UnknownOrgError(OrgError):
    """Raised when an org_id is not known."""


class DuplicateDomainError(OrgError):
    """Raised when a domain is already claimed by any org."""


class UnknownDomainError(OrgError):
    """Raised when a domain is not claimed by the org."""


class AlreadyVerifiedError(OrgError):
    """Raised when verifying an already-verified domain."""


class SSOPreconditionError(OrgError):
    """Raised when binding SSO without a verified domain."""


class SuspendedOrgError(OrgError):
    """Raised when mutating a suspended org."""


class SeqOrderError(OrgError):
    """Raised when a mutation seq does not strictly increase."""


def _canonical(parts: Tuple[str, ...]) -> bytes:
    return b"\x00".join(p.encode("utf-8") for p in parts)


@dataclass(frozen=True)
class Org:
    org_id: str
    name: str
    slug: str
    created_seq: int
    status: str  # "active" | "suspended"
    digest: str


@dataclass(frozen=True)
class DomainClaim:
    domain: str
    org_id: str
    claimed_seq: int
    verified: bool
    verified_seq: Optional[int]
    digest: str


@dataclass(frozen=True)
class SSOConfig:
    org_id: str
    provider: str
    entity_id: str
    acs_url: Optional[str]
    bound_seq: int
    digest: str
    # client_secret is stored as a masked verifier only.
    secret_verifier: Optional[str] = None


class OrgManager:
    """Multi-tenant org ledger: orgs, domain claims, SSO bindings."""

    def __init__(self, seed: Optional[bytes] = None) -> None:
        self._seed = seed if seed is not None else secrets.token_bytes(32)
        self._orgs: Dict[str, Org] = {}
        self._slugs: Dict[str, str] = {}  # slug -> org_id
        self._domains: Dict[str, DomainClaim] = {}  # domain -> claim
        self._sso: Dict[str, SSOConfig] = {}  # org_id -> config
        self._audit: List[Dict[str, Any]] = []
        self._last_seq = 0
        self._counter = 0

    # -- internals ------------------------------------------------------

    def _check_seq(self, seq: int) -> None:
        if not isinstance(seq, int) or isinstance(seq, bool):
            raise TypeError("seq must be an int")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} does not strictly increase (last={self._last_seq})"
            )

    def _record(self, seq: int, kind: str, payload: Dict[str, Any]) -> None:
        self._last_seq = seq
        self._audit.append({"seq": seq, "kind": kind, "payload": payload})

    def _org(self, org_id: str) -> Org:
        if not isinstance(org_id, str) or not org_id.startswith(_ORG_ID_PREFIX):
            raise ValueError(f"malformed org_id: {org_id!r}")
        try:
            return self._orgs[org_id]
        except KeyError:
            raise UnknownOrgError(f"unknown org: {org_id}") from None

    def _require_active(self, org: Org) -> None:
        if org.status != "active":
            raise SuspendedOrgError(f"org is suspended: {org.org_id}")

    def _mint_org_id(self, slug: str, seq: int) -> str:
        self._counter += 1
        raw = hmac.new(
            self._seed,
            _canonical(("org", slug, str(seq), str(self._counter))),
            hashlib.sha256,
        ).hexdigest()[:_ID_HEX_LEN]
        return f"{_ORG_ID_PREFIX}{raw}"

    @staticmethod
    def _digest(parts: Tuple[str, ...]) -> str:
        return "sha256:" + hashlib.sha256(_canonical(parts)).hexdigest()

    @staticmethod
    def _mask_secret(secret: str) -> str:
        return "masked:" + hmac.new(
            b"org-manager-secret-mask", secret.encode("utf-8"), hashlib.sha256
        ).hexdigest()[:16]

    # -- orgs -----------------------------------------------------------

    def create(self, name: str, seq: int, slug: Optional[str] = None) -> Org:
        """Create an org. ``slug`` defaults to a slugified ``name``."""
        self._check_seq(seq)
        if not isinstance(name, str) or not name.strip():
            raise ValueError("name must be a non-empty string")
        if slug is None:
            slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
        if not isinstance(slug, str) or not _SLUG_RE.match(slug):
            raise ValueError(f"malformed slug: {slug!r}")
        if slug in self._slugs:
            raise DuplicateOrgError(f"slug already taken: {slug}")
        org_id = self._mint_org_id(slug, seq)
        digest = self._digest(("org", org_id, name.strip(), slug, str(seq)))
        org = Org(
            org_id=org_id,
            name=name.strip(),
            slug=slug,
            created_seq=seq,
            status="active",
            digest=digest,
        )
        self._orgs[org_id] = org
        self._slugs[slug] = org_id
        self._record(seq, "org.created",
                     {"org_id": org_id, "name": org.name, "slug": slug})
        return org

    def get(self, org_id: str) -> Org:
        return self._org(org_id)

    def suspend(self, org_id: str, seq: int) -> Org:
        self._check_seq(seq)
        org = self._org(org_id)
        org = Org(org_id=org.org_id, name=org.name, slug=org.slug,
                  created_seq=org.created_seq, status="suspended",
                  digest=org.digest)
        self._orgs[org_id] = org
        self._record(seq, "org.suspended", {"org_id": org_id})
        return org

    def reactivate(self, org_id: str, seq: int) -> Org:
        self._check_seq(seq)
        org = self._org(org_id)
        org = Org(org_id=org.org_id, name=org.name, slug=org.slug,
                  created_seq=org.created_seq, status="active",
                  digest=org.digest)
        self._orgs[org_id] = org
        self._record(seq, "org.reactivated", {"org_id": org_id})
        return org

    # -- domains --------------------------------------------------------

    def domain(self, org_id: str, domain: str, seq: int) -> DomainClaim:
        """Claim a domain for an org (starts unverified)."""
        self._check_seq(seq)
        org = self._org(org_id)
        self._require_active(org)
        if not isinstance(domain, str):
            raise ValueError("domain must be a string")
        domain = domain.strip().lower()
        if not _DOMAIN_RE.match(domain):
            raise ValueError(f"malformed domain: {domain!r}")
        if domain in self._domains:
            raise DuplicateDomainError(f"domain already claimed: {domain}")
        digest = self._digest(("domain", domain, org_id, str(seq)))
        claim = DomainClaim(domain=domain, org_id=org_id, claimed_seq=seq,
                            verified=False, verified_seq=None, digest=digest)
        self._domains[domain] = claim
        self._record(seq, "domain.claimed",
                     {"org_id": org_id, "domain": domain})
        return claim

    def verify_domain(self, org_id: str, domain: str, seq: int) -> DomainClaim:
        """Mark a claimed domain verified (host reports proof-of-control)."""
        self._check_seq(seq)
        org = self._org(org_id)
        self._require_active(org)
        domain = domain.strip().lower()
        claim = self._domains.get(domain)
        if claim is None or claim.org_id != org_id:
            raise UnknownDomainError(
                f"domain not claimed by org: {domain}")
        if claim.verified:
            raise AlreadyVerifiedError(f"domain already verified: {domain}")
        claim = DomainClaim(domain=claim.domain, org_id=claim.org_id,
                            claimed_seq=claim.claimed_seq, verified=True,
                            verified_seq=seq, digest=claim.digest)
        self._domains[domain] = claim
        self._record(seq, "domain.verified",
                     {"org_id": org_id, "domain": domain})
        return claim

    def domains_of(self, org_id: str) -> Tuple[DomainClaim, ...]:
        self._org(org_id)
        return tuple(
            sorted(
                (c for c in self._domains.values() if c.org_id == org_id),
                key=lambda c: c.domain,
            )
        )

    # -- sso ------------------------------------------------------------

    def sso(self, org_id: str, provider: str, seq: int,
            entity_id: str = "", acs_url: Optional[str] = None,
            client_secret: Optional[str] = None) -> SSOConfig:
        """Bind (or re-bind) an SSO provider to an org.

        Requires at least one verified domain — the anti-takeover rule.
        """
        self._check_seq(seq)
        org = self._org(org_id)
        self._require_active(org)
        if provider not in _SSO_PROVIDERS:
            raise ValueError(f"unknown provider: {provider!r}")
        if not any(c.verified for c in self.domains_of(org_id)):
            raise SSOPreconditionError(
                f"org has no verified domain: {org_id}")
        if not isinstance(entity_id, str) or not entity_id.strip():
            raise ValueError("entity_id must be a non-empty string")
        digest = self._digest(
            ("sso", org_id, provider, entity_id.strip(), str(seq)))
        cfg = SSOConfig(
            org_id=org_id,
            provider=provider,
            entity_id=entity_id.strip(),
            acs_url=acs_url,
            bound_seq=seq,
            digest=digest,
            secret_verifier=(
                self._mask_secret(client_secret)
                if client_secret is not None else None
            ),
        )
        self._sso[org_id] = cfg
        self._record(seq, "sso.bound",
                     {"org_id": org_id, "provider": provider,
                      "entity_id": entity_id.strip()})
        return cfg

    def sso_of(self, org_id: str) -> Optional[SSOConfig]:
        self._org(org_id)
        return self._sso.get(org_id)

    # -- views ----------------------------------------------------------

    def audit(self) -> Tuple[Dict[str, Any], ...]:
        return tuple(self._audit)

    def as_dict(self) -> Dict[str, Any]:
        """Ledger snapshot. Secrets never appear here — only verifiers."""
        return {
            "version": ORG_MANAGER_VERSION,
            "schema": SCHEMA_PIN,
            "last_seq": self._last_seq,
            "orgs": [
                {
                    "org_id": o.org_id,
                    "name": o.name,
                    "slug": o.slug,
                    "created_seq": o.created_seq,
                    "status": o.status,
                    "digest": o.digest,
                }
                for o in sorted(self._orgs.values(),
                                key=lambda o: o.created_seq)
            ],
            "domains": [
                {
                    "domain": c.domain,
                    "org_id": c.org_id,
                    "claimed_seq": c.claimed_seq,
                    "verified": c.verified,
                    "verified_seq": c.verified_seq,
                    "digest": c.digest,
                }
                for c in sorted(self._domains.values(),
                                key=lambda c: c.domain)
            ],
            "sso": [
                {
                    "org_id": c.org_id,
                    "provider": c.provider,
                    "entity_id": c.entity_id,
                    "acs_url": c.acs_url,
                    "bound_seq": c.bound_seq,
                    "digest": c.digest,
                    "secret_verifier": c.secret_verifier,
                }
                for c in sorted(self._sso.values(),
                                key=lambda c: c.org_id)
            ],
            "audit": [dict(e) for e in self._audit],
        }


def org_manager_audit_event(seq: int, kind: str,
                            payload: Dict[str, Any]) -> Dict[str, Any]:
    """Build a canonical audit event dict for external audit pipelines."""
    return {"seq": seq, "kind": kind, "payload": dict(payload),
            "schema": SCHEMA_PIN}
