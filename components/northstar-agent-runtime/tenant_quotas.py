"""Per-tenant resource quotas: limits, enforcement, and resets.

A ``TenantQuotas`` ledger books host-reported resource limits and
consumption as a deterministic single-host state machine:

- ``set(tenant_id, resource, seq, limit)`` pins a quota: the tenant may
  consume at most ``limit`` units of ``resource``. Re-setting replaces
  the limit and keeps the usage so far (upsert, not duplicate).
- ``check(tenant_id, resource, amount, seq)`` enforces it: returns a
  frozen ``QuotaDecision`` whose ``allowed`` verdict is *data* (never
  raised). An allowed check books the consumption; an over-limit check
  leaves usage untouched. Unknown tenants or unpinned quotas read as
  ``allowed=False`` data (fail-closed).
- ``reset(tenant_id, resource, seq)`` zeroes the tenant's usage for the
  resource (e.g. period rollover), returning a frozen ``ResetRecord``.

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (no wall-clock), RLock-guarded, fail-closed taxonomy, stdlib-only
plus the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, ``audit.ndjson/1`` events, version pin
``tenant-quotas.v1``, schema pin ``northstar.tenant-quotas.v1``,
``main()`` self-check.

Honest scope: this module books *host-reported* usage figures and
cannot observe real CPU, memory, disk, or network consumption; a
``QuotaDecision`` answers "did the host's books permit this amount",
never "did the hardware permit it". It cannot detect usage the host
never reports, and it cannot prove a quota is fair — capacity planning
is the caller's job. Pair with ``budget_approval_combo`` for money and
with ``rate_limiter`` for per-second velocity.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
TENANT_QUOTAS_VERSION = "tenant-quotas.v1"

#: Schema pin carried by records and audit events.
TENANT_QUOTAS_SCHEMA = "northstar.tenant-quotas.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned vocabulary of metered resources (quota drift is detectable).
RESOURCES = (
    "cpu_ms",
    "memory_bytes",
    "storage_bytes",
    "api_calls",
    "tokens",
    "egress_bytes",
    "sessions",
    "jobs",
)

#: Largest quota limit bookable (batch-5 JCS discipline: |n| < 2**53).
MAX_LIMIT = 2**53 - 1

#: Denial reasons carried by QuotaDecision (verdicts are data).
REASON_OK = "ok"
REASON_QUOTA_EXCEEDED = "quota-exceeded"
REASON_UNKNOWN_QUOTA = "unknown-quota"


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class TenantQuotasError(ValueError):
    """Base for all tenant-quota structural problems and refused transitions."""


class BadQuotaError(TenantQuotasError):
    """Quota definition is malformed (bad tenant, resource, or limit)."""


class UnknownQuotaError(TenantQuotasError):
    """No quota is pinned for the (tenant, resource) pair."""


class BadConsumptionError(TenantQuotasError):
    """A check amount is malformed (not a positive int)."""


class SeqOrderError(TenantQuotasError):
    """Caller seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"{name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TenantQuotasError(f"{name} must be a non-empty string")
    return value.strip()


def _check_resource(resource: Any) -> str:
    if not isinstance(resource, str) or resource not in RESOURCES:
        raise BadQuotaError(
            f"resource must be one of {RESOURCES}, got {resource!r}"
        )
    return resource


def _check_limit(limit: Any) -> int:
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or limit < 1
        or limit > MAX_LIMIT
    ):
        raise BadQuotaError(
            f"limit must be an int in [1, {MAX_LIMIT}], got {limit!r}"
        )
    return limit


def _check_amount(amount: Any) -> int:
    if isinstance(amount, bool) or not isinstance(amount, int) or amount < 1:
        raise BadConsumptionError(
            f"amount must be a positive int, got {amount!r}"
        )
    return amount


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        jcs_canonical_json([TENANT_QUOTAS_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class QuotaRecord:
    """One pinned quota limit (frozen). ``used`` is bookkeeping, not a pin."""

    quota_id: str
    tenant_id: str
    resource: str
    limit: int
    used: int
    seq: int
    digest: str
    schema: str = TENANT_QUOTAS_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "quota", self.quota_id, self.tenant_id, self.resource,
            self.limit, self.seq,
        )


@dataclass(frozen=True)
class QuotaDecision:
    """One enforcement verdict (frozen). ``allowed=False`` is data."""

    check_id: str
    tenant_id: str
    resource: str
    amount: int
    allowed: bool
    reason: str
    used_before: int
    used_after: int
    limit: int
    seq: int
    digest: str
    schema: str = TENANT_QUOTAS_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "check", self.check_id, self.tenant_id, self.resource, self.amount,
            self.allowed, self.reason, self.used_before, self.used_after,
            self.limit, self.seq,
        )


@dataclass(frozen=True)
class ResetRecord:
    """One usage reset (frozen)."""

    reset_id: str
    tenant_id: str
    resource: str
    used_before: int
    seq: int
    digest: str
    schema: str = TENANT_QUOTAS_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "reset", self.reset_id, self.tenant_id, self.resource,
            self.used_before, self.seq,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

KIND_QUOTA_SET = "tenant-quota.set"
KIND_QUOTA_UPDATED = "tenant-quota.updated"
KIND_QUOTA_CHECKED = "tenant-quota.checked"
KIND_QUOTA_EXCEEDED = "tenant-quota.exceeded"
KIND_QUOTA_RESET = "tenant-quota.reset"
KIND_REJECTED = "tenant-quota.rejected"
_KINDS = (
    KIND_QUOTA_SET, KIND_QUOTA_UPDATED, KIND_QUOTA_CHECKED,
    KIND_QUOTA_EXCEEDED, KIND_QUOTA_RESET, KIND_REJECTED,
)


def tenant_quotas_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the tenant-quotas module."""
    if kind not in _KINDS:
        raise TenantQuotasError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise TenantQuotasError("detail must be a mapping")
    # Usage histories never cross the audit boundary; ids + pins only.
    banned = {"history", "usage_history", "consumptions"}
    if any(k in detail for k in banned):
        raise TenantQuotasError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": TENANT_QUOTAS_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class TenantQuotas:
    """Deterministic per-tenant resource-quota ledger.

    All state mutations take a caller-supplied ``seq`` (monotonic
    logical time); no wall-clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._quotas: Dict[Tuple[str, str], QuotaRecord] = {}  # (t,r) -> record
        self._used: Dict[Tuple[str, str], int] = {}            # (t,r) -> used
        self._quota_seq = 0
        self._check_seq_no = 0
        self._reset_seq_no = 0
        self._audit_log: List[Dict[str, Any]] = []

    # -- internals ------------------------------------------------------

    def _claim_seq(self, seq: int) -> int:
        _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} did not strictly increase (last={self._last_seq})"
            )
        self._last_seq = seq
        return seq

    def _reject_locked(self, reason: str) -> None:
        self._audit_log.append(
            tenant_quotas_audit_event(
                KIND_REJECTED, {"reason": reason}, self._last_seq
            )
        )

    def _audit_locked(self, kind: str, detail: Mapping[str, Any]) -> None:
        self._audit_log.append(
            tenant_quotas_audit_event(kind, detail, self._last_seq)
        )

    # -- mutations ------------------------------------------------------

    def set(self, tenant_id: str, resource: str, seq: int, limit: int) -> QuotaRecord:
        """Pin (or replace) a quota limit for (tenant, resource).

        Re-setting is an upsert: the usage booked so far is preserved and
        only the limit changes. The replaced record stays readable only
        via the audit trail.
        """
        with self._lock:
            tenant_id = _check_nonempty_str(tenant_id, "tenant_id")
            _check_resource(resource)
            limit = _check_limit(limit)
            self._claim_seq(seq)
            key = (tenant_id, resource)
            existing = self._quotas.get(key)
            self._quota_seq += 1
            quota_id = f"quot-{self._quota_seq}"
            used = self._used.get(key, 0)
            record = QuotaRecord(
                quota_id=quota_id, tenant_id=tenant_id, resource=resource,
                limit=limit, used=used, seq=seq,
                digest=_pin("quota", quota_id, tenant_id, resource, limit, seq),
            )
            self._quotas[key] = record
            kind = KIND_QUOTA_UPDATED if existing is not None else KIND_QUOTA_SET
            self._audit_locked(
                kind,
                {
                    "quota_id": quota_id, "tenant_id": tenant_id,
                    "resource": resource, "limit": limit,
                    "digest": record.digest,
                },
            )
            return record

    def check(
        self, tenant_id: str, resource: str, amount: int, seq: int
    ) -> QuotaDecision:
        """Enforce the quota for a consumption of ``amount`` units.

        The verdict is a frozen record: ``allowed=False`` is data, never
        raised. An allowed check books the consumption; an over-limit or
        unknown-quota check leaves usage untouched. Failed mutations
        consume their seq.
        """
        with self._lock:
            tenant_id = _check_nonempty_str(tenant_id, "tenant_id")
            resource = _check_resource(resource)
            amount = _check_amount(amount)
            self._claim_seq(seq)
            key = (tenant_id, resource)
            record = self._quotas.get(key)
            self._check_seq_no += 1
            check_id = f"chk-{self._check_seq_no}"
            if record is None:
                decision = QuotaDecision(
                    check_id=check_id, tenant_id=tenant_id, resource=resource,
                    amount=amount, allowed=False,
                    reason=REASON_UNKNOWN_QUOTA, used_before=0, used_after=0,
                    limit=0, seq=seq,
                    digest=_pin(
                        "check", check_id, tenant_id, resource, amount, False,
                        REASON_UNKNOWN_QUOTA, 0, 0, 0, seq,
                    ),
                )
                self._audit_locked(
                    KIND_QUOTA_EXCEEDED,
                    {
                        "check_id": check_id, "tenant_id": tenant_id,
                        "resource": resource,
                        "reason": REASON_UNKNOWN_QUOTA,
                        "digest": decision.digest,
                    },
                )
                return decision
            used_before = self._used.get(key, 0)
            if used_before + amount <= record.limit:
                used_after = used_before + amount
                self._used[key] = used_after
                allowed, reason, kind = True, REASON_OK, KIND_QUOTA_CHECKED
            else:
                used_after = used_before
                allowed, reason, kind = False, REASON_QUOTA_EXCEEDED, KIND_QUOTA_EXCEEDED
            decision = QuotaDecision(
                check_id=check_id, tenant_id=tenant_id, resource=resource,
                amount=amount, allowed=allowed, reason=reason,
                used_before=used_before, used_after=used_after,
                limit=record.limit, seq=seq,
                digest=_pin(
                    "check", check_id, tenant_id, resource, amount, allowed,
                    reason, used_before, used_after, record.limit, seq,
                ),
            )
            self._audit_locked(
                kind,
                {
                    "check_id": check_id, "tenant_id": tenant_id,
                    "resource": resource, "allowed": allowed,
                    "reason": reason, "digest": decision.digest,
                },
            )
            return decision

    def reset(self, tenant_id: str, resource: str, seq: int) -> ResetRecord:
        """Zero the tenant's usage for the resource (period rollover)."""
        with self._lock:
            tenant_id = _check_nonempty_str(tenant_id, "tenant_id")
            resource = _check_resource(resource)
            self._claim_seq(seq)
            key = (tenant_id, resource)
            if key not in self._quotas:
                self._reject_locked("unknown-quota")
                raise UnknownQuotaError(
                    f"no quota pinned for ({tenant_id!r}, {resource!r})"
                )
            used_before = self._used.get(key, 0)
            self._used[key] = 0
            self._reset_seq_no += 1
            reset_id = f"rst-{self._reset_seq_no}"
            record = ResetRecord(
                reset_id=reset_id, tenant_id=tenant_id, resource=resource,
                used_before=used_before, seq=seq,
                digest=_pin(
                    "reset", reset_id, tenant_id, resource, used_before, seq
                ),
            )
            self._audit_locked(
                KIND_QUOTA_RESET,
                {
                    "reset_id": reset_id, "tenant_id": tenant_id,
                    "resource": resource, "digest": record.digest,
                },
            )
            return record

    # -- views ----------------------------------------------------------

    def quota(self, tenant_id: str, resource: str) -> QuotaRecord:
        """Return the pinned quota record (usage included) for (t, r)."""
        with self._lock:
            key = (
                _check_nonempty_str(tenant_id, "tenant_id"),
                _check_resource(resource),
            )
            record = self._quotas.get(key)
            if record is None:
                raise UnknownQuotaError(
                    f"no quota pinned for ({tenant_id!r}, {resource!r})"
                )
            used = self._used.get(key, 0)
            return QuotaRecord(
                quota_id=record.quota_id, tenant_id=record.tenant_id,
                resource=record.resource, limit=record.limit, used=used,
                seq=record.seq,
                digest=_pin(
                    "quota", record.quota_id, record.tenant_id,
                    record.resource, record.limit, record.seq,
                ),
            )

    def usage_of(self, tenant_id: str, resource: str) -> int:
        """Return the booked usage for (tenant, resource)."""
        with self._lock:
            key = (
                _check_nonempty_str(tenant_id, "tenant_id"),
                _check_resource(resource),
            )
            if key not in self._quotas:
                raise UnknownQuotaError(
                    f"no quota pinned for ({tenant_id!r}, {resource!r})"
                )
            return self._used.get(key, 0)

    def remaining_of(self, tenant_id: str, resource: str) -> int:
        """Return limit - used for (tenant, resource)."""
        with self._lock:
            key = (
                _check_nonempty_str(tenant_id, "tenant_id"),
                _check_resource(resource),
            )
            record = self._quotas.get(key)
            if record is None:
                raise UnknownQuotaError(
                    f"no quota pinned for ({tenant_id!r}, {resource!r})"
                )
            return record.limit - self._used.get(key, 0)

    def quota_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(f"{t}/{r}" for (t, r) in self._quotas))

    def tenant_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted({t for (t, _r) in self._quotas}))

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit_log)


def main() -> None:
    quotas = TenantQuotas()
    q = quotas.set("acme", "api_calls", 1, 100)
    assert q.verify() and q.limit == 100
    d1 = quotas.check("acme", "api_calls", 40, 2)
    assert d1.allowed and d1.verify() and d1.used_after == 40
    d2 = quotas.check("acme", "api_calls", 60, 3)
    assert d2.allowed and d2.used_after == 100
    d3 = quotas.check("acme", "api_calls", 1, 4)   # exactly at cap -> denied
    assert not d3.allowed and d3.reason == "quota-exceeded"
    assert quotas.usage_of("acme", "api_calls") == 100
    d4 = quotas.check("ghost", "api_calls", 1, 5)   # unknown tenant -> data denial
    assert not d4.allowed and d4.reason == "unknown-quota"
    r = quotas.reset("acme", "api_calls", 6)
    assert r.verify() and quotas.usage_of("acme", "api_calls") == 0
    q2 = quotas.set("acme", "api_calls", 7, 50)     # upsert keeps usage(0)
    assert q2.limit == 50 and q2.verify()
    print("tenant-quotas OK: set, check, reset, upsert, unknown-quota")
    return None


if __name__ == "__main__":
    main()
