"""White-label branding: tenant themes, custom domains, and brand assets.

Reseller/white-label bookkeeping informed by the SaaS playbook
(Stripipe-style custom domains, theme token systems): a tenant
registers a theme (color tokens, logo reference, fonts), claims a
custom domain (host-reported DNS verification), and pins brand
assets (logo, favicon, og image) by content digest.

House rules: no wall-clock (caller-supplied strictly-increasing int
seqs on mutating calls; ``SeqOrderError`` on rewind; failed mutations
consume their seq — fail-closed ledger position), frozen dataclasses,
stdlib-only, sha256 digest pins over type-tagged canonical JSON
(bool != int; no floats; |n| < 2^53), RLock-guarded,
``audit.ndjson/1`` events.

Honest boundary: this module books *reported* branding decisions
(GIGO). It cannot prove a domain resolves to the tenant, cannot
verify that an asset's pixels match a digest claim beyond hashing
host-supplied bytes, and cannot observe a CDN serving the theme.
Pair with ``org_manager`` for tenant identity and
``cdn_config``-style edge wiring for production delivery.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

try:  # standard guarded import used across the batch line
    from canonical_json import jcs_dumps
except Exception:  # pragma: no cover - fallback when run standalone

    def jcs_dumps(obj: Any) -> bytes:
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


#: Version pin for this module's record shape.
WHITE_LABEL_VERSION = "white-label.v1"

#: Schema pin carried by records and audit events.
WHITE_LABEL_SCHEMA = "northstar.white-label.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned theme token names.
TOKEN_NAMES = (
    "primary",
    "secondary",
    "background",
    "surface",
    "text",
    "accent",
    "error",
)

#: Pinned brand-asset kinds.
ASSET_KINDS = ("logo", "logo_dark", "favicon", "og_image", "app_icon")

#: Pinned tenant lifecycle states.
STATE_ACTIVE = "active"
STATE_SUSPENDED = "suspended"
STATE_DELETED = "deleted"

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$")
_COLOR_RE = re.compile(r"^#[0-9A-Fa-f]{6}$")

_AUDIT_KINDS = (
    "tenant-registered",
    "theme-set",
    "domain-claimed",
    "domain-verified",
    "domain-released",
    "asset-pinned",
    "asset-unpinned",
    "tenant-suspended",
    "tenant-reactivated",
    "rejected",
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class WhiteLabelError(Exception):
    """Base error for the white-label module."""


class UnknownTenantError(WhiteLabelError):
    """The tenant id is not registered."""


class DuplicateTenantError(WhiteLabelError):
    """A tenant with this id already exists."""


class DuplicateDomainError(WhiteLabelError):
    """The custom domain is already claimed by a tenant."""


class UnknownDomainError(WhiteLabelError):
    """The domain is not claimed by this tenant."""


class BadThemeError(WhiteLabelError):
    """Theme tokens fail validation."""


class BadAssetError(WhiteLabelError):
    """Brand-asset declaration fails validation."""


class UnknownAssetError(WhiteLabelError):
    """No asset pinned for this (tenant, kind)."""


class TenantStateError(WhiteLabelError):
    """Mutation refused because the tenant is not active."""


class SeqOrderError(WhiteLabelError):
    """Caller-supplied seq is not strictly increasing."""


# ---------------------------------------------------------------------------
# Canonical encoding + digest helpers
# ---------------------------------------------------------------------------


def _tag(value: Any) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) >= 2**53:
            raise WhiteLabelError(f"int out of safe range: {value!r}")
        return value
    if isinstance(value, float):
        raise WhiteLabelError(f"floats are not canonicalizable: {value!r}")
    if isinstance(value, str):
        return value
    if isinstance(value, (tuple, list)):
        return [_tag(v) for v in value]
    if isinstance(value, Mapping):
        return {str(k): _tag(value[k]) for k in sorted(value, key=str)}
    raise WhiteLabelError(f"uncanonizable value: {type(value).__name__}")


def _pin(*parts: Any) -> str:
    payload = jcs_dumps(_tag(list(parts)))
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _check_seq(seq: Any, name: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError(f"{name} must be a non-negative int, got {seq!r}")
    return seq


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TenantRecord:
    tenant_id: str
    name: str
    seq: int
    state: str
    theme_digest: str | None
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            "tenant", self.tenant_id, self.name, self.seq, self.state, self.theme_digest
        )


@dataclass(frozen=True)
class ThemeRecord:
    theme_id: str
    tenant_id: str
    tokens: Mapping[str, str]
    font_family: str
    border_radius: int
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            "theme",
            self.theme_id,
            self.tenant_id,
            dict(self.tokens),
            self.font_family,
            self.border_radius,
            self.seq,
        )


@dataclass(frozen=True)
class DomainRecord:
    domain: str
    tenant_id: str
    seq: int
    verified: bool
    verification_token: str | None
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            "domain",
            self.domain,
            self.tenant_id,
            self.seq,
            self.verified,
            self.verification_token,
        )


@dataclass(frozen=True)
class AssetRecord:
    asset_id: str
    tenant_id: str
    kind: str
    content_digest: str
    label: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            "asset",
            self.asset_id,
            self.tenant_id,
            self.kind,
            self.content_digest,
            self.label,
            self.seq,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def white_label_audit_event(kind: str, seq: int, **detail: Any) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the white-label module."""
    if kind not in _AUDIT_KINDS:
        raise WhiteLabelError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "white-label",
        "module_version": WHITE_LABEL_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class WhiteLabel:
    """Tenant branding registry: themes, custom domains, brand assets."""

    def __init__(self, seed: str = "white-label") -> None:
        self._lock = threading.RLock()
        self._seed = seed
        self._seq = -1
        self._tenants: dict[str, TenantRecord] = {}
        self._themes: dict[str, ThemeRecord] = {}
        self._domains: dict[str, DomainRecord] = {}
        self._assets: dict[tuple[str, str], AssetRecord] = {}
        self._audit_log: list[Mapping[str, Any]] = []
        self._t_counter = 0
        self._theme_counter = 0
        self._asset_counter = 0

    # -- internals ------------------------------------------------------

    def _audit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit_log.append(white_label_audit_event(kind, seq, **detail))

    def _take_seq(self, seq: int) -> int:
        seq = _check_seq(seq, "seq")
        if seq <= self._seq:
            self._audit("rejected", seq, reason="seq-not-increasing")
            raise SeqOrderError(f"seq must be strictly increasing; last={self._seq}, got={seq}")
        self._seq = seq
        return seq

    def _require_active(self, tenant_id: str) -> TenantRecord:
        rec = self._tenants.get(tenant_id)
        if rec is None:
            raise UnknownTenantError(f"unknown tenant: {tenant_id!r}")
        if rec.state != STATE_ACTIVE:
            raise TenantStateError(f"tenant {tenant_id!r} is {rec.state}")
        return rec

    # -- tenants --------------------------------------------------------

    def register_tenant(self, tenant_id: str, name: str, seq: int) -> TenantRecord:
        """Register a new branding tenant."""
        with self._lock:
            self._take_seq(seq)
            if not tenant_id or not isinstance(tenant_id, str):
                self._audit("rejected", seq, op="register-tenant", reason="bad-tenant-id")
                raise WhiteLabelError("tenant_id must be a non-empty string")
            if not name or not isinstance(name, str):
                self._audit("rejected", seq, op="register-tenant", reason="bad-name")
                raise WhiteLabelError("name must be a non-empty string")
            if tenant_id in self._tenants:
                self._audit("rejected", seq, op="register-tenant", reason="duplicate")
                raise DuplicateTenantError(f"tenant already registered: {tenant_id!r}")
            self._t_counter += 1
            digest = _pin("tenant", tenant_id, name, seq, STATE_ACTIVE, None)
            rec = TenantRecord(
                tenant_id=tenant_id, name=name, seq=seq,
                state=STATE_ACTIVE, theme_digest=None, digest=digest,
            )
            self._tenants[tenant_id] = rec
            self._audit("tenant-registered", seq, tenant_id=tenant_id, digest=digest)
            return rec

    def suspend_tenant(self, tenant_id: str, seq: int) -> TenantRecord:
        with self._lock:
            self._take_seq(seq)
            rec = self._tenants.get(tenant_id)
            if rec is None:
                self._audit("rejected", seq, op="suspend-tenant", reason="unknown-tenant")
                raise UnknownTenantError(f"unknown tenant: {tenant_id!r}")
            new = TenantRecord(
                tenant_id=rec.tenant_id, name=rec.name, seq=seq,
                state=STATE_SUSPENDED, theme_digest=rec.theme_digest,
                digest=_pin("tenant", rec.tenant_id, rec.name, seq, STATE_SUSPENDED, rec.theme_digest),
            )
            self._tenants[tenant_id] = new
            self._audit("tenant-suspended", seq, tenant_id=tenant_id)
            return new

    def reactivate_tenant(self, tenant_id: str, seq: int) -> TenantRecord:
        with self._lock:
            self._take_seq(seq)
            rec = self._tenants.get(tenant_id)
            if rec is None:
                self._audit("rejected", seq, op="reactivate-tenant", reason="unknown-tenant")
                raise UnknownTenantError(f"unknown tenant: {tenant_id!r}")
            new = TenantRecord(
                tenant_id=rec.tenant_id, name=rec.name, seq=seq,
                state=STATE_ACTIVE, theme_digest=rec.theme_digest,
                digest=_pin("tenant", rec.tenant_id, rec.name, seq, STATE_ACTIVE, rec.theme_digest),
            )
            self._tenants[tenant_id] = new
            self._audit("tenant-reactivated", seq, tenant_id=tenant_id)
            return new

    # -- themes ---------------------------------------------------------

    def theme(
        self,
        tenant_id: str,
        tokens: Mapping[str, str],
        seq: int,
        font_family: str = "system-ui",
        border_radius: int = 8,
    ) -> ThemeRecord:
        """Set the tenant's theme token set."""
        with self._lock:
            self._take_seq(seq)
            self._require_active(tenant_id)
            if not isinstance(tokens, Mapping):
                self._audit("rejected", seq, op="theme", reason="bad-tokens-type")
                raise BadThemeError("tokens must be a mapping")
            missing = [t for t in TOKEN_NAMES if t not in tokens]
            if missing:
                self._audit("rejected", seq, op="theme", reason="missing-tokens", missing=missing)
                raise BadThemeError(f"missing token names: {missing}")
            extra = [t for t in tokens if t not in TOKEN_NAMES]
            if extra:
                self._audit("rejected", seq, op="theme", reason="extra-tokens", extra=extra)
                raise BadThemeError(f"unknown token names: {extra}")
            for name, value in tokens.items():
                if not isinstance(value, str) or not _COLOR_RE.match(value):
                    self._audit("rejected", seq, op="theme", reason="bad-color", token=name)
                    raise BadThemeError(f"token {name!r} must be #RRGGBB, got {value!r}")
            if not font_family or not isinstance(font_family, str):
                self._audit("rejected", seq, op="theme", reason="bad-font")
                raise BadThemeError("font_family must be a non-empty string")
            if isinstance(border_radius, bool) or not isinstance(border_radius, int) or not 0 <= border_radius <= 64:
                self._audit("rejected", seq, op="theme", reason="bad-radius")
                raise BadThemeError("border_radius must be an int in 0..64")
            self._theme_counter += 1
            theme_id = f"thm-{self._theme_counter}"
            frozen_tokens = {k: tokens[k] for k in TOKEN_NAMES}
            digest = _pin("theme", theme_id, tenant_id, frozen_tokens, font_family, border_radius, seq)
            rec = ThemeRecord(
                theme_id=theme_id, tenant_id=tenant_id, tokens=frozen_tokens,
                font_family=font_family, border_radius=border_radius, seq=seq, digest=digest,
            )
            self._themes[tenant_id] = rec
            old = self._tenants[tenant_id]
            self._tenants[tenant_id] = TenantRecord(
                tenant_id=old.tenant_id, name=old.name, seq=old.seq,
                state=old.state, theme_digest=digest,
                digest=_pin("tenant", old.tenant_id, old.name, old.seq, old.state, digest),
            )
            self._audit("theme-set", seq, tenant_id=tenant_id, theme_id=theme_id, digest=digest)
            return rec

    def get_theme(self, tenant_id: str) -> ThemeRecord | None:
        with self._lock:
            return self._themes.get(tenant_id)

    # -- domains --------------------------------------------------------

    def domain(self, tenant_id: str, domain: str, seq: int) -> DomainRecord:
        """Claim a custom domain for the tenant (unverified until :meth:`verify_domain`)."""
        with self._lock:
            self._take_seq(seq)
            self._require_active(tenant_id)
            if not isinstance(domain, str) or not _DOMAIN_RE.match(domain):
                self._audit("rejected", seq, op="domain", reason="bad-domain")
                raise WhiteLabelError(f"invalid domain: {domain!r}")
            normalized = domain.lower()
            if normalized in self._domains:
                self._audit("rejected", seq, op="domain", reason="duplicate-domain")
                raise DuplicateDomainError(f"domain already claimed: {normalized!r}")
            token = _pin("domain-token", self._seed, tenant_id, normalized, seq)[7:39]
            digest = _pin("domain", normalized, tenant_id, seq, False, token)
            rec = DomainRecord(
                domain=normalized, tenant_id=tenant_id, seq=seq,
                verified=False, verification_token=token, digest=digest,
            )
            self._domains[normalized] = rec
            self._audit("domain-claimed", seq, tenant_id=tenant_id, domain=normalized, digest=digest)
            return rec

    def verify_domain(self, tenant_id: str, domain: str, seq: int, presented_token: str) -> DomainRecord:
        """Mark the domain verified once the host reports a matching DNS TXT token."""
        with self._lock:
            self._take_seq(seq)
            self._require_active(tenant_id)
            normalized = domain.lower() if isinstance(domain, str) else ""
            rec = self._domains.get(normalized)
            if rec is None or rec.tenant_id != tenant_id:
                self._audit("rejected", seq, op="verify-domain", reason="unknown-domain")
                raise UnknownDomainError(f"domain not claimed by tenant: {domain!r}")
            if rec.verification_token != presented_token:
                self._audit("rejected", seq, op="verify-domain", reason="token-mismatch")
                raise WhiteLabelError("verification token mismatch")
            new = DomainRecord(
                domain=rec.domain, tenant_id=rec.tenant_id, seq=seq,
                verified=True, verification_token=None,
                digest=_pin("domain", rec.domain, rec.tenant_id, seq, True, None),
            )
            self._domains[normalized] = new
            self._audit("domain-verified", seq, tenant_id=tenant_id, domain=normalized)
            return new

    def release_domain(self, tenant_id: str, domain: str, seq: int) -> DomainRecord:
        """Release a claimed domain so it can be claimed elsewhere."""
        with self._lock:
            self._take_seq(seq)
            self._require_active(tenant_id)
            normalized = domain.lower() if isinstance(domain, str) else ""
            rec = self._domains.get(normalized)
            if rec is None or rec.tenant_id != tenant_id:
                self._audit("rejected", seq, op="release-domain", reason="unknown-domain")
                raise UnknownDomainError(f"domain not claimed by tenant: {domain!r}")
            del self._domains[normalized]
            self._audit("domain-released", seq, tenant_id=tenant_id, domain=normalized)
            return rec

    def domains_for(self, tenant_id: str) -> tuple[DomainRecord, ...]:
        with self._lock:
            return tuple(sorted(
                (r for r in self._domains.values() if r.tenant_id == tenant_id),
                key=lambda r: r.domain,
            ))

    # -- assets ---------------------------------------------------------

    def assets(self, tenant_id: str, kind: str, content_digest: str, seq: int, label: str = "") -> AssetRecord:
        """Pin a brand asset (logo, favicon, ...) to a content digest."""
        with self._lock:
            self._take_seq(seq)
            self._require_active(tenant_id)
            if kind not in ASSET_KINDS:
                self._audit("rejected", seq, op="assets", reason="bad-kind")
                raise BadAssetError(f"unknown asset kind: {kind!r}")
            if not isinstance(content_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", content_digest):
                self._audit("rejected", seq, op="assets", reason="bad-digest")
                raise BadAssetError("content_digest must be 'sha256:' + 64 hex chars")
            if not isinstance(label, str):
                self._audit("rejected", seq, op="assets", reason="bad-label")
                raise BadAssetError("label must be a string")
            self._asset_counter += 1
            asset_id = f"ast-{self._asset_counter}"
            digest = _pin("asset", asset_id, tenant_id, kind, content_digest, label, seq)
            rec = AssetRecord(
                asset_id=asset_id, tenant_id=tenant_id, kind=kind,
                content_digest=content_digest, label=label, seq=seq, digest=digest,
            )
            self._assets[(tenant_id, kind)] = rec
            self._audit("asset-pinned", seq, tenant_id=tenant_id, asset_kind=kind,
                        asset_id=asset_id, digest=digest)
            return rec

    def get_asset(self, tenant_id: str, kind: str) -> AssetRecord:
        with self._lock:
            rec = self._assets.get((tenant_id, kind))
            if rec is None:
                raise UnknownAssetError(f"no {kind!r} asset for tenant {tenant_id!r}")
            return rec

    def unpin_asset(self, tenant_id: str, kind: str, seq: int) -> AssetRecord:
        with self._lock:
            self._take_seq(seq)
            self._require_active(tenant_id)
            rec = self._assets.get((tenant_id, kind))
            if rec is None:
                self._audit("rejected", seq, op="unpin-asset", reason="unknown-asset")
                raise UnknownAssetError(f"no {kind!r} asset for tenant {tenant_id!r}")
            del self._assets[(tenant_id, kind)]
            self._audit("asset-unpinned", seq, tenant_id=tenant_id, asset_kind=kind,
                        asset_id=rec.asset_id)
            return rec

    # -- views ----------------------------------------------------------

    def tenant(self, tenant_id: str) -> TenantRecord:
        with self._lock:
            rec = self._tenants.get(tenant_id)
            if rec is None:
                raise UnknownTenantError(f"unknown tenant: {tenant_id!r}")
            return rec

    def tenant_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._tenants))

    def audit_log(self) -> tuple[Mapping[str, Any], ...]:
        with self._lock:
            return tuple(self._audit_log)

    def as_dict(self) -> Mapping[str, Any]:
        with self._lock:
            return {
                "schema": WHITE_LABEL_SCHEMA,
                "module_version": WHITE_LABEL_VERSION,
                "tenants": len(self._tenants),
                "domains": len(self._domains),
                "assets": len(self._assets),
                "last_seq": self._seq,
            }


def main() -> None:
    wl = WhiteLabel(seed="self-check")
    t = wl.register_tenant("acme", "Acme Corp", 1)
    th = wl.theme("acme", {k: "#112233" for k in TOKEN_NAMES}, 2)
    d = wl.domain("acme", "app.acme.example", 3)
    vd = wl.verify_domain("acme", "app.acme.example", 4, d.verification_token or "")
    a = wl.assets("acme", "logo", "sha256:" + "ab" * 32, 5, label="primary")
    assert t.verify() and th.verify() and d.verify() and vd.verify() and a.verify()
    assert vd.verified is True
    print("white-label OK: register, theme, domain, verify, assets, pins")


if __name__ == "__main__":
    main()
