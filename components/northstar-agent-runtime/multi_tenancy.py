"""Multi-tenancy — tenant isolation policy bookkeeping (thirty-first batch).

Research note (SaaS multi-tenancy literature): the classic isolation
ladder runs *pool* (fully shared, tenants separated only by a tenant
discriminator — the cheapest, weakest), *bridge* (shared compute, data
isolated per tenant — the common SaaS middle ground), *silo* (dedicated
stack per tenant — strongest, most expensive). AWS SaaS Factory's
"deployment and isolation models" describe exactly this spectrum. This
module takes the intersection for a deterministic single-host ledger:

* **Tenants as pinned records**: ``create`` mints a frozen
  ``TenantRecord`` with a ``sha256:`` digest pin; tenant ids are
  globally unique and never recycled.
* **Isolation as policy, not wiring**: ``isolate`` books the declared
  isolation *model* plus the isolated *scopes* per tenant, with a
  pinned model/scope compatibility table enforced fail-closed.
* **Migrations as first-class records**: ``migrate`` moves a tenant up
  the ladder freely; moving *down* (weakening isolation) requires an
  explicit ``downgrade_ack=True`` and is otherwise refused fail-closed.
* **Failed mutations consume their seq** (batch-21 ledger discipline);
  seqs are caller-supplied strictly-increasing ints — no wall-clock.

House rules: frozen dataclasses, caller int seqs, RLock guarding,
fail-closed taxonomy, stdlib-only, sha256 digest pins over type-tagged
canonical payloads (bool != int; NaN/inf and |n| >= 2**53 refused),
``audit.ndjson/1`` events.

Honest boundary: this module books *declared* isolation policies. It
cannot prove that row-level discrimination, key separation, or network
segmentation are actually enforced on a real stack — a consumer pairs
these frozen records with its own provisioning/admission checks.
GIGO on tenant ids and host-reported scopes.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

#: Version pin for this module's record shape.
MULTI_TENANCY_VERSION = "multi-tenancy.v1"

#: Schema pin carried by records and audit events.
MULTI_TENANCY_SCHEMA = "northstar.multi-tenancy.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

# ---------------------------------------------------------------------------
# Pinned vocabularies
# ---------------------------------------------------------------------------

#: Isolation models, ordered weakest -> strongest.
MODEL_POOL = "pool"
MODEL_BRIDGE = "bridge"
MODEL_SILO = "silo"
ISOLATION_MODELS = (MODEL_POOL, MODEL_BRIDGE, MODEL_SILO)
_MODEL_RANK = {MODEL_POOL: 0, MODEL_BRIDGE: 1, MODEL_SILO: 2}

#: Isolatable scopes.
SCOPE_COMPUTE = "compute"
SCOPE_DATA = "data"
SCOPE_NETWORK = "network"
SCOPE_KEYS = "keys"
ISOLATION_SCOPES = (SCOPE_COMPUTE, SCOPE_DATA, SCOPE_NETWORK, SCOPE_KEYS)

#: Model -> minimum scope set required. Silo isolates everything; bridge
#: isolates data + keys at minimum; pool isolates data only (discriminator).
_MODEL_MIN_SCOPES = {
    MODEL_SILO: frozenset(ISOLATION_SCOPES),
    MODEL_BRIDGE: frozenset({SCOPE_DATA, SCOPE_KEYS}),
    MODEL_POOL: frozenset({SCOPE_DATA}),
}

#: Tenant plans.
PLAN_FREE = "free"
PLAN_TEAM = "team"
PLAN_ENTERPRISE = "enterprise"
TENANT_PLANS = (PLAN_FREE, PLAN_TEAM, PLAN_ENTERPRISE)

#: Audit event kinds.
KIND_TENANT_CREATED = "tenant-created"
KIND_ISOLATED = "tenant-isolated"
KIND_MIGRATED = "tenant-migrated"
KIND_REJECTED = "tenant-rejected"
_KINDS = (KIND_TENANT_CREATED, KIND_ISOLATED, KIND_MIGRATED, KIND_REJECTED)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class MultiTenancyError(ValueError):
    """Base error for the multi-tenancy module."""


class BadTenantError(MultiTenancyError):
    """Malformed tenant id, name, or plan."""


class DuplicateTenantError(MultiTenancyError):
    """A tenant with this id already exists."""


class UnknownTenantError(MultiTenancyError):
    """No tenant with this id exists."""


class BadIsolationError(MultiTenancyError):
    """Unknown isolation model."""


class BadScopeError(MultiTenancyError):
    """Unknown isolation scope."""


class IncompatibleScopeError(MultiTenancyError):
    """Scope set is incompatible with the chosen isolation model."""


class DuplicateIsolationError(MultiTenancyError):
    """This tenant already has an identical isolation policy."""


class BadMigrationError(MultiTenancyError):
    """Malformed migration request."""


class SameModelError(MultiTenancyError):
    """The target model equals the tenant's current model."""


class DowngradeRefusedError(MultiTenancyError):
    """Weakening isolation requires downgrade_ack=True."""


class SeqOrderError(MultiTenancyError):
    """Mutation seq is not a strictly increasing int."""


# ---------------------------------------------------------------------------
# Canonical digest helpers (type-tagged; batch-5 JCS discipline)
# ---------------------------------------------------------------------------


def _tag(value: Any) -> Any:
    """Type-tag a value so bool != int and NaN/inf/|n|>=2**53 are refused."""
    if value is None:
        return {"t": "none"}
    if isinstance(value, bool):
        return {"t": "bool", "v": value}
    if isinstance(value, int):
        if abs(value) >= 2**53:
            raise BadTenantError("integer out of safe range")
        return {"t": "int", "v": value}
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise BadTenantError("non-finite float refused")
        raise BadTenantError("float values refused")
    if isinstance(value, str):
        return {"t": "str", "v": value}
    if isinstance(value, (list, tuple)):
        return {"t": "list", "v": [_tag(v) for v in value]}
    if isinstance(value, dict):
        return {
            "t": "dict",
            "v": sorted(
                ((_tag(k), _tag(v)) for k, v in value.items()),
                key=lambda kv: json.dumps(kv[0], sort_keys=True),
            ),
        }
    raise BadTenantError(f"unsupported value type: {type(value).__name__}")


def _pin(*parts: Any) -> str:
    """sha256: digest pin over type-tagged canonical payload."""
    payload = json.dumps([_tag(p) for p in parts], sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TenantRecord:
    """Frozen tenant registration record."""

    tenant_id: str
    name: str
    plan: str
    seq: int
    prev_digest: str
    digest: str

    def verify(self) -> bool:
        """Re-derive the digest pin; True iff intact."""
        return self.digest == _pin(
            "tenant", self.tenant_id, self.name, self.plan, self.seq, self.prev_digest
        )


@dataclass(frozen=True)
class IsolationRecord:
    """Frozen per-tenant isolation policy record."""

    record_id: str
    tenant_id: str
    model: str
    scopes: tuple
    seq: int
    prev_digest: str
    digest: str

    def verify(self) -> bool:
        """Re-derive the digest pin; True iff intact."""
        return self.digest == _pin(
            "isolation",
            self.record_id,
            self.tenant_id,
            self.model,
            sorted(self.scopes),
            self.seq,
            self.prev_digest,
        )


@dataclass(frozen=True)
class MigrationRecord:
    """Frozen tenant isolation-model migration record."""

    record_id: str
    tenant_id: str
    from_model: str
    to_model: str
    downgrade: bool
    seq: int
    prev_digest: str
    digest: str

    def verify(self) -> bool:
        """Re-derive the digest pin; True iff intact."""
        return self.digest == _pin(
            "migration",
            self.record_id,
            self.tenant_id,
            self.from_model,
            self.to_model,
            self.downgrade,
            self.seq,
            self.prev_digest,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def multi_tenancy_audit_event(kind: str, seq: int, tenant_id: str, detail: Mapping[str, Any] | None = None) -> dict:
    """Build an ``audit.ndjson/1`` event.

    Carries ids + digest pins only — tenant *names* never cross the audit
    boundary.
    """
    if kind not in _KINDS:
        raise MultiTenancyError(f"unknown audit kind: {kind!r}")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise MultiTenancyError("bad audit seq")
    if not isinstance(tenant_id, str) or not tenant_id:
        raise MultiTenancyError("bad tenant id")
    safe_detail: dict = {}
    for key in ("record_id", "digest", "model", "from_model", "to_model", "plan", "downgrade", "scopes"):
        if detail and key in detail:
            value = detail[key]
            if key == "scopes":
                value = sorted(value)
            safe_detail[key] = value
    event = {
        "schema": AUDIT_SCHEMA,
        "module": MULTI_TENANCY_VERSION,
        "kind": kind,
        "seq": seq,
        "tenant_id": tenant_id,
        "detail": safe_detail,
    }
    event["digest"] = _pin("audit", kind, seq, tenant_id, safe_detail)
    return event


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class MultiTenancy:
    """Deterministic tenant isolation policy ledger."""

    def __init__(self, seed: str = "northstar") -> None:
        if not isinstance(seed, str) or not seed:
            raise BadTenantError("seed must be a non-empty str")
        self._lock = threading.RLock()
        self._seed = seed
        self._last_seq = -1
        self._tenants: dict[str, TenantRecord] = {}
        self._isolation: dict[str, IsolationRecord] = {}
        self._migrations: dict[str, MigrationRecord] = {}
        self._migration_counter = 0
        self._isolation_counter = 0
        self._audit_log: list[dict] = []

    # -- internal --------------------------------------------------------

    def _consume_seq(self, seq: Any) -> None:
        """Validate and consume a mutation seq (failed mutations burn it)."""
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
            raise SeqOrderError("seq must be a non-negative int")
        if seq <= self._last_seq:
            raise SeqOrderError("seq must be strictly increasing")
        self._last_seq = seq

    def _audit(self, kind: str, seq: int, tenant_id: str, detail: Mapping[str, Any] | None = None) -> None:
        self._audit_log.append(multi_tenancy_audit_event(kind, seq, tenant_id, detail))

    def _reject(self, seq: int, tenant_id: str, error: MultiTenancyError) -> None:
        self._audit(kind=KIND_REJECTED, seq=seq, tenant_id=tenant_id, detail={"digest": str(error)})
        raise error

    def _check_tenant_id(self, tenant_id: Any) -> None:
        if not isinstance(tenant_id, str) or not tenant_id or len(tenant_id) > 128:
            raise BadTenantError("tenant_id must be a non-empty str (<=128 chars)")

    # -- mutations ---------------------------------------------------------

    def create(self, tenant_id: str, seq: int, name: str = "", plan: str = PLAN_FREE) -> TenantRecord:
        """Register a tenant. Ids are globally unique and never recycled."""
        with self._lock:
            self._consume_seq(seq)
            try:
                self._check_tenant_id(tenant_id)
                if not isinstance(name, str) or len(name) > 256:
                    raise BadTenantError("name must be a str (<=256 chars)")
                if plan not in TENANT_PLANS:
                    raise BadTenantError(f"unknown plan: {plan!r}")
                if tenant_id in self._tenants:
                    raise DuplicateTenantError(f"tenant already exists: {tenant_id!r}")
            except MultiTenancyError as exc:
                tid = tenant_id if isinstance(tenant_id, str) and tenant_id else "unknown"
                self._reject(seq, tid, exc)
            record = TenantRecord(
                tenant_id=tenant_id,
                name=name,
                plan=plan,
                seq=seq,
                prev_digest=self._chain_digest(),
                digest="",
            )
            digest = _pin("tenant", tenant_id, name, plan, seq, record.prev_digest)
            record = TenantRecord(
                tenant_id=tenant_id, name=name, plan=plan, seq=seq,
                prev_digest=record.prev_digest, digest=digest,
            )
            self._tenants[tenant_id] = record
            self._audit(KIND_TENANT_CREATED, seq, tenant_id, {"digest": digest, "plan": plan})
            return record

    def isolate(self, tenant_id: str, seq: int, model: str, scopes: Sequence[str] = ()) -> IsolationRecord:
        """Book the tenant's isolation policy.

        Scope sets must satisfy the model's minimum (silo: all four;
        bridge: data + keys; pool: data only, no extras).
        """
        with self._lock:
            self._consume_seq(seq)
            try:
                self._check_tenant_id(tenant_id)
                if tenant_id not in self._tenants:
                    raise UnknownTenantError(f"unknown tenant: {tenant_id!r}")
                if model not in ISOLATION_MODELS:
                    raise BadIsolationError(f"unknown model: {model!r}")
                scope_list = list(scopes)
                for scope in scope_list:
                    if scope not in ISOLATION_SCOPES:
                        raise BadScopeError(f"unknown scope: {scope!r}")
                scope_set = frozenset(scope_list)
                if len(scope_set) != len(scope_list):
                    raise BadScopeError("duplicate scopes")
                minimum = _MODEL_MIN_SCOPES[model]
                if model == MODEL_POOL:
                    if scope_set != minimum:
                        raise IncompatibleScopeError("pool model pins exactly the data scope")
                elif not minimum.issubset(scope_set):
                    raise IncompatibleScopeError(
                        f"model {model!r} requires at least {sorted(minimum)}"
                    )
                current = self._isolation.get(tenant_id)
                if current is not None and current.model == model and frozenset(current.scopes) == scope_set:
                    raise DuplicateIsolationError("identical isolation policy already booked")
            except MultiTenancyError as exc:
                self._reject(seq, tenant_id if isinstance(tenant_id, str) and tenant_id else "unknown", exc)
            self._isolation_counter += 1
            record_id = f"iso-{self._isolation_counter}"
            prev_digest = self._chain_digest()
            digest = _pin(
                "isolation", record_id, tenant_id, model, sorted(scope_set), seq, prev_digest
            )
            record = IsolationRecord(
                record_id=record_id,
                tenant_id=tenant_id,
                model=model,
                scopes=tuple(sorted(scope_set)),
                seq=seq,
                prev_digest=prev_digest,
                digest=digest,
            )
            self._isolation[tenant_id] = record
            self._audit(KIND_ISOLATED, seq, tenant_id, {"record_id": record_id, "digest": digest, "model": model, "scopes": sorted(scope_set)})
            return record

    def migrate(self, tenant_id: str, seq: int, target_model: str, downgrade_ack: bool = False) -> MigrationRecord:
        """Move a tenant between isolation models.

        Up the ladder (pool -> bridge -> silo) is always allowed; moving
        *down* requires ``downgrade_ack=True`` and is otherwise refused
        fail-closed.
        """
        with self._lock:
            self._consume_seq(seq)
            try:
                self._check_tenant_id(tenant_id)
                if tenant_id not in self._tenants:
                    raise UnknownTenantError(f"unknown tenant: {tenant_id!r}")
                if target_model not in ISOLATION_MODELS:
                    raise BadMigrationError(f"unknown target model: {target_model!r}")
                if not isinstance(downgrade_ack, bool):
                    raise BadMigrationError("downgrade_ack must be bool")
                current = self._isolation.get(tenant_id)
                from_model = current.model if current is not None else MODEL_POOL
                if target_model == from_model:
                    raise SameModelError(f"tenant already on model {from_model!r}")
                downgrade = _MODEL_RANK[target_model] < _MODEL_RANK[from_model]
                if downgrade and not downgrade_ack:
                    raise DowngradeRefusedError(
                        f"weakening isolation {from_model} -> {target_model} needs downgrade_ack=True"
                    )
            except MultiTenancyError as exc:
                self._reject(seq, tenant_id if isinstance(tenant_id, str) and tenant_id else "unknown", exc)
            self._migration_counter += 1
            record_id = f"mig-{self._migration_counter}"
            prev_digest = self._chain_digest()
            digest = _pin(
                "migration", record_id, tenant_id, from_model, target_model,
                downgrade, seq, prev_digest,
            )
            record = MigrationRecord(
                record_id=record_id,
                tenant_id=tenant_id,
                from_model=from_model,
                to_model=target_model,
                downgrade=downgrade,
                seq=seq,
                prev_digest=prev_digest,
                digest=digest,
            )
            self._migrations[record_id] = record
            # Apply the new model as the tenant's current isolation policy,
            # keeping the previously declared scopes where compatible.
            if current is not None:
                scope_set = frozenset(current.scopes)
                minimum = _MODEL_MIN_SCOPES[target_model]
                if target_model == MODEL_POOL:
                    scope_set = minimum
                else:
                    scope_set = scope_set | minimum
            else:
                scope_set = _MODEL_MIN_SCOPES[target_model]
            self._apply_isolation_locked(tenant_id, target_model, scope_set, seq)
            self._audit(
                KIND_MIGRATED, seq, tenant_id,
                {"record_id": record_id, "digest": digest, "from_model": from_model,
                 "to_model": target_model, "downgrade": downgrade},
            )
            return record

    # -- internal apply ----------------------------------------------------

    def _chain_digest(self) -> str:
        digests = [r.digest for r in self._tenants.values()]
        digests += [r.digest for r in self._isolation.values()]
        digests += [r.digest for r in self._migrations.values()]
        return _pin("chain", self._seed, sorted(digests)) if digests else _pin("chain", self._seed, "genesis")

    def _apply_isolation_locked(self, tenant_id: str, model: str, scope_set: frozenset, seq: int) -> IsolationRecord:
        """Book an isolation record without re-consuming the seq."""
        self._isolation_counter += 1
        record_id = f"iso-{self._isolation_counter}"
        prev_digest = self._chain_digest()
        digest = _pin("isolation", record_id, tenant_id, model, sorted(scope_set), seq, prev_digest)
        record = IsolationRecord(
            record_id=record_id, tenant_id=tenant_id, model=model,
            scopes=tuple(sorted(scope_set)), seq=seq,
            prev_digest=prev_digest, digest=digest,
        )
        self._isolation[tenant_id] = record
        self._audit(KIND_ISOLATED, seq, tenant_id, {"record_id": record_id, "digest": digest, "model": model, "scopes": sorted(scope_set)})
        return record

    # -- views (pure: validate seq shape, consume nothing) -----------------

    def tenant(self, tenant_id: str) -> TenantRecord:
        """Return the tenant record; raises UnknownTenantError."""
        with self._lock:
            if tenant_id not in self._tenants:
                raise UnknownTenantError(f"unknown tenant: {tenant_id!r}")
            return self._tenants[tenant_id]

    def tenant_ids(self) -> tuple:
        """Sorted tenant ids."""
        with self._lock:
            return tuple(sorted(self._tenants))

    def isolation(self, tenant_id: str) -> IsolationRecord | None:
        """Current isolation policy, or None if never set."""
        with self._lock:
            if tenant_id not in self._tenants:
                raise UnknownTenantError(f"unknown tenant: {tenant_id!r}")
            return self._isolation.get(tenant_id)

    def migration(self, record_id: str) -> MigrationRecord:
        """Return a migration record by id."""
        with self._lock:
            if record_id not in self._migrations:
                raise BadMigrationError(f"unknown migration: {record_id!r}")
            return self._migrations[record_id]

    def migration_ids(self) -> tuple:
        """Sorted migration record ids."""
        with self._lock:
            return tuple(sorted(self._migrations))

    def audit(self, seq: int) -> dict:
        """Digest-pinned summary view (pure observation)."""
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
            raise SeqOrderError("seq must be a non-negative int")
        with self._lock:
            summary = {
                "schema": AUDIT_SCHEMA,
                "module": MULTI_TENANCY_VERSION,
                "tenants": len(self._tenants),
                "isolated": len(self._isolation),
                "migrations": len(self._migrations),
                "tenant_ids": sorted(self._tenants),
                "audit_events": len(self._audit_log),
            }
            summary["digest"] = _pin("audit-summary", summary)
            return summary

    def audit_log(self) -> tuple:
        """Copy of the audit event trail."""
        with self._lock:
            return tuple(self._audit_log)

    def as_dict(self) -> dict:
        """Snapshot of the ledger (ids + pins only; no tenant names)."""
        with self._lock:
            return {
                "schema": MULTI_TENANCY_SCHEMA,
                "version": MULTI_TENANCY_VERSION,
                "tenants": {tid: {"plan": r.plan, "seq": r.seq, "digest": r.digest} for tid, r in self._tenants.items()},
                "isolation": {
                    tid: {"model": r.model, "scopes": list(r.scopes), "digest": r.digest}
                    for tid, r in self._isolation.items()
                },
                "migrations": {
                    rid: {"tenant_id": r.tenant_id, "from": r.from_model, "to": r.to_model, "downgrade": r.downgrade, "digest": r.digest}
                    for rid, r in self._migrations.items()
                },
            }


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    """Self-check: create, isolate, migrate, refusals, audit."""
    mt = MultiTenancy(seed="selfcheck")
    t = mt.create("acme", 0, name="Acme Corp", plan="team")
    assert t.verify()
    iso = mt.isolate("acme", 1, "silo", ("compute", "data", "network", "keys"))
    assert iso.verify() and iso.model == "silo"
    # downgrade without ack must be refused fail-closed
    try:
        mt.migrate("acme", 2, "pool")
        raise AssertionError("downgrade should have been refused")
    except DowngradeRefusedError:
        pass
    mig = mt.migrate("acme", 3, "pool", downgrade_ack=True)
    assert mig.verify() and mig.downgrade and mig.to_model == "pool"
    assert mt.isolation("acme").model == "pool"
    summary = mt.audit(4)
    assert summary["tenants"] == 1 and summary["migrations"] == 1
    print("multi-tenancy OK: create, isolate, migrate, refusals, audit")


if __name__ == "__main__":
    main()
