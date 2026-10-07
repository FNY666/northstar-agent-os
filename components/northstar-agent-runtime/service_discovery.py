"""Service registry bookkeeping: a ledger for service discovery decisions.

A ``ServiceDiscovery`` books host-reported service-registry decisions
(Consul/Eureka shaped) as a deterministic single-host state machine:

- ``register(service_id, service_name, address, seq, port=..., tags=())``
  books one service instance as a frozen ``ServiceRecord`` pinned by a
  ``sha256:`` digest. ``service_id`` is the unique instance id (never
  recycled); ``service_name`` is the lookup label shared by all instances
  of one logical service. Duplicate ids refuse fail-closed.
- ``report(service_id, healthy, seq)`` books a host-reported health
  verdict as a frozen ``HealthReport`` — verdicts are data, health state is
  ``healthy``/``unhealthy``/``unknown`` (unknown until the host reports).
- ``deregister(service_id, seq, reason="")`` books a terminal
  ``DeregisterRecord`` — the id is retired and can never be re-registered.
- ``lookup(service_name, seq, healthy_only=True)`` is a pure read view
  returning a frozen ``LookupReport`` of instance ids (sorted), optionally
  restricted to instances whose host-reported health is ``healthy``.
- ``list_services(seq)`` is a pure read view returning a frozen
  ``ServiceCatalog`` of registered service names (sorted).

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (no wall-clock), RLock-guarded, fail-closed taxonomy, stdlib-only
plus the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, ``audit.ndjson/1`` events, version pin
``service-discovery.v1``, schema pin ``northstar.service-discovery.v1``,
``main()`` self-check.

Honest scope: this module books *decisions* about a registry — there is
no network, no gossip, no health-check socket probing, no TTL scheduler.
Health is whatever the host reports (GIGO); a ``healthy`` record means the
host said so, never that the endpoint answered. Pair with a real registry
agent for production.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
SERVICE_DISCOVERY_VERSION = "service-discovery.v1"

#: Schema pin carried by records and audit events.
SERVICE_DISCOVERY_SCHEMA = "northstar.service-discovery.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pin: maximum service id / service name length in chars.
MAX_NAME_CHARS = 256

#: Pin: maximum tags per registration.
MAX_TAGS = 32

_HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.\-]{0,251}[a-z0-9])?$")

_VALID_HEALTH = ("healthy", "unhealthy", "unknown")

# Reason vocabulary for deregister.
_VALID_DEREGISTER_REASONS = ("scale-in", "deploy", "failure", "manual", "expired")


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------


class ServiceDiscoveryError(Exception):
    """Base class for all service_discovery errors."""


class BadServiceError(ServiceDiscoveryError):
    """The service id, name, address, port, or tags are malformed."""


class DuplicateServiceError(ServiceDiscoveryError):
    """A registration with this service id already exists (or was retired)."""


class UnknownServiceError(ServiceDiscoveryError):
    """The referenced service id is unknown."""


class DeregisteredServiceError(ServiceDiscoveryError):
    """The service id has been deregistered and is retired."""


class BadHealthError(ServiceDiscoveryError):
    """The reported health value is not a bool."""


class BadLookupError(ServiceDiscoveryError):
    """The lookup request is malformed (name or flags)."""


class SeqOrderError(ServiceDiscoveryError):
    """Caller seq did not strictly increase (or had a bad shape)."""


class AuditKindError(ServiceDiscoveryError):
    """Unknown audit event kind."""


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

KIND_REGISTERED = "service-discovery.registered"
KIND_REPORTED = "service-discovery.reported"
KIND_DEREGISTERED = "service-discovery.deregistered"
KIND_REJECTED = "service-discovery.rejected"
_AUDIT_KINDS = (KIND_REGISTERED, KIND_REPORTED, KIND_DEREGISTERED, KIND_REJECTED)


def service_discovery_audit_event(
    kind: str,
    seq: int,
    service_id: str = "",
    service_name: str = "",
    detail: str = "",
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1`` event; ids and digest pins only.

    Addresses and tags never cross the audit boundary — only the service
    id, the service name, and a digest pin of the record.
    """
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise SeqOrderError("seq must be a non-negative int")
    return {
        "schema": AUDIT_SCHEMA,
        "module": SERVICE_DISCOVERY_VERSION,
        "kind": kind,
        "seq": seq,
        "service_id": service_id,
        "service_name": service_name,
        "detail": detail,
    }


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BadServiceError(f"{name} must be a non-empty string")
    value = value.strip()
    if len(value) > MAX_NAME_CHARS:
        raise BadServiceError(f"{name} exceeds {MAX_NAME_CHARS} chars")
    return value


def _check_name(value: Any) -> str:
    name = _check_id(value, "service_name").lower()
    if not _HOST_RE.match(name):
        raise BadServiceError(
            "service_name must be a DNS-shaped label"
        )
    return name


def _check_address(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BadServiceError("address must be a non-empty string")
    value = value.strip().lower()
    if " " in value or "\t" in value or "/" in value or ":" in value:
        raise BadServiceError("address must be a bare host or IP, no scheme/port")
    if len(value) > 253:
        raise BadServiceError("address exceeds 253 chars")
    return value


def _check_port(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadServiceError("port must be an int")
    if not 1 <= value <= 65535:
        raise BadServiceError("port must be in 1-65535")
    return value


def _check_tags(value: Any) -> Tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, (tuple, list)):
        raise BadServiceError("tags must be a tuple/list of strings")
    if len(value) > MAX_TAGS:
        raise BadServiceError(f"tags exceed {MAX_TAGS} entries")
    out: List[str] = []
    for tag in value:
        if not isinstance(tag, str) or not tag.strip():
            raise BadServiceError("each tag must be a non-empty string")
        out.append(tag.strip())
    return tuple(out)


def _check_reason(value: Any) -> str:
    if not isinstance(value, str) or value not in _VALID_DEREGISTER_REASONS:
        raise BadServiceError(
            f"reason must be one of {sorted(_VALID_DEREGISTER_REASONS)}"
        )
    return value


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        jcs_canonical_json([SERVICE_DISCOVERY_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ServiceRecord:
    """One pinned service instance registration (frozen)."""

    service_id: str
    service_name: str
    address: str
    port: int
    tags: Tuple[str, ...]
    seq: int
    digest: str
    schema: str = SERVICE_DISCOVERY_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "register",
            self.service_id,
            self.service_name,
            self.address,
            self.port,
            list(self.tags),
            self.seq,
        )


@dataclass(frozen=True)
class HealthReport:
    """One host-reported health verdict (frozen)."""

    service_id: str
    health: str
    seq: int
    digest: str
    schema: str = SERVICE_DISCOVERY_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "report", self.service_id, self.health, self.seq
        )


@dataclass(frozen=True)
class DeregisterRecord:
    """One terminal deregistration (frozen)."""

    service_id: str
    reason: str
    seq: int
    digest: str
    schema: str = SERVICE_DISCOVERY_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "deregister", self.service_id, self.reason, self.seq
        )


@dataclass(frozen=True)
class LookupReport:
    """One lookup result (frozen). Instance ids sorted; verdicts are data."""

    service_name: str
    healthy_only: bool
    instance_ids: Tuple[str, ...]
    seq: int
    digest: str
    schema: str = SERVICE_DISCOVERY_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "lookup",
            self.service_name,
            self.healthy_only,
            list(self.instance_ids),
            self.seq,
        )


@dataclass(frozen=True)
class ServiceCatalog:
    """One catalog snapshot (frozen). Service names sorted."""

    service_names: Tuple[str, ...]
    seq: int
    digest: str
    schema: str = SERVICE_DISCOVERY_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "catalog", list(self.service_names), self.seq
        )


# ---------------------------------------------------------------------------
# The registry
# ---------------------------------------------------------------------------


class ServiceDiscovery:
    """Deterministic service registry bookkeeping.

    All state mutations take a caller-supplied ``seq`` (monotonic logical
    time); no wall-clock is read anywhere. Failed mutations consume their
    seq (fail-closed ledger position). Read views (``lookup``,
    ``list_services``) validate the seq shape but neither consume it nor
    write audit rows.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._services: Dict[str, ServiceRecord] = {}
        self._health: Dict[str, str] = {}
        self._deregistered: Dict[str, DeregisterRecord] = {}
        self._health_reports: Dict[str, List[HealthReport]] = {}
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _take_seq(self, seq: Any) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq})"
            )
        self._last_seq = seq
        return seq

    def _shape_seq(self, seq: Any) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("seq must be a non-negative int")
        return seq

    def _reject(self, seq: int, service_id: str, service_name: str, why: str) -> None:
        self._audit.append(
            service_discovery_audit_event(
                KIND_REJECTED, seq, service_id, service_name, why
            )
        )

    # -- mutations ---------------------------------------------------------

    def register(
        self,
        service_id: str,
        service_name: str,
        address: str,
        seq: int,
        port: int = 80,
        tags: Any = (),
    ) -> ServiceRecord:
        """Book one service instance registration."""
        with self._lock:
            seq = self._take_seq(seq)
            try:
                sid = _check_id(service_id, "service_id")
                name = _check_name(service_name)
                addr = _check_address(address)
                p = _check_port(port)
                t = _check_tags(tags)
            except ServiceDiscoveryError as exc:
                self._reject(seq, str(service_id), str(service_name), str(exc))
                raise
            if sid in self._deregistered:
                err = DeregisteredServiceError(
                    f"service id {sid!r} was deregistered and is retired"
                )
                self._reject(seq, sid, name, str(err))
                raise err
            if sid in self._services:
                err = DuplicateServiceError(f"duplicate service id: {sid!r}")
                self._reject(seq, sid, name, str(err))
                raise err
            digest = _pin("register", sid, name, addr, p, list(t), seq)
            rec = ServiceRecord(
                service_id=sid,
                service_name=name,
                address=addr,
                port=p,
                tags=t,
                seq=seq,
                digest=digest,
            )
            self._services[sid] = rec
            self._health[sid] = "unknown"
            self._health_reports[sid] = []
            self._audit.append(
                service_discovery_audit_event(
                    KIND_REGISTERED, seq, sid, name, digest
                )
            )
            return rec

    def report(self, service_id: str, healthy: bool, seq: int) -> HealthReport:
        """Book a host-reported health verdict for one instance."""
        with self._lock:
            seq = self._take_seq(seq)
            try:
                sid = _check_id(service_id, "service_id")
                if not isinstance(healthy, bool):
                    raise BadHealthError("healthy must be a bool")
            except ServiceDiscoveryError as exc:
                self._reject(seq, str(service_id), "", str(exc))
                raise
            if sid in self._deregistered:
                err = DeregisteredServiceError(
                    f"service id {sid!r} was deregistered and is retired"
                )
                self._reject(seq, sid, "", str(err))
                raise err
            if sid not in self._services:
                err = UnknownServiceError(f"unknown service id: {sid!r}")
                self._reject(seq, sid, "", str(err))
                raise err
            health = "healthy" if healthy else "unhealthy"
            digest = _pin("report", sid, health, seq)
            rec = HealthReport(
                service_id=sid, health=health, seq=seq, digest=digest
            )
            self._health[sid] = health
            self._health_reports[sid].append(rec)
            self._audit.append(
                service_discovery_audit_event(
                    KIND_REPORTED, seq, sid, self._services[sid].service_name, digest
                )
            )
            return rec

    def deregister(self, service_id: str, seq: int, reason: str = "manual") -> DeregisterRecord:
        """Book a terminal deregistration; the id is retired."""
        with self._lock:
            seq = self._take_seq(seq)
            try:
                sid = _check_id(service_id, "service_id")
                r = _check_reason(reason)
            except ServiceDiscoveryError as exc:
                self._reject(seq, str(service_id), "", str(exc))
                raise
            if sid in self._deregistered:
                err = DeregisteredServiceError(
                    f"service id {sid!r} was already deregistered"
                )
                self._reject(seq, sid, "", str(err))
                raise err
            if sid not in self._services:
                err = UnknownServiceError(f"unknown service id: {sid!r}")
                self._reject(seq, sid, "", str(err))
                raise err
            name = self._services[sid].service_name
            digest = _pin("deregister", sid, r, seq)
            rec = DeregisterRecord(
                service_id=sid, reason=r, seq=seq, digest=digest
            )
            del self._services[sid]
            del self._health[sid]
            self._deregistered[sid] = rec
            self._audit.append(
                service_discovery_audit_event(
                    KIND_DEREGISTERED, seq, sid, name, digest
                )
            )
            return rec

    # -- read views --------------------------------------------------------

    def lookup(
        self, service_name: str, seq: int, healthy_only: bool = True
    ) -> LookupReport:
        """Return registered instance ids for one service name (pure view)."""
        with self._lock:
            seq = self._shape_seq(seq)
            name = _check_name(service_name)
            if not isinstance(healthy_only, bool):
                raise BadLookupError("healthy_only must be a bool")
            ids = sorted(
                sid
                for sid, rec in self._services.items()
                if rec.service_name == name
                and (not healthy_only or self._health.get(sid) == "healthy")
            )
            digest = _pin("lookup", name, healthy_only, ids, seq)
            return LookupReport(
                service_name=name,
                healthy_only=healthy_only,
                instance_ids=tuple(ids),
                seq=seq,
                digest=digest,
            )

    def list_services(self, seq: int) -> ServiceCatalog:
        """Return all registered service names (pure view)."""
        with self._lock:
            seq = self._shape_seq(seq)
            names = sorted({rec.service_name for rec in self._services.values()})
            digest = _pin("catalog", names, seq)
            return ServiceCatalog(
                service_names=tuple(names), seq=seq, digest=digest
            )

    # -- views -------------------------------------------------------------

    def service(self, service_id: str) -> ServiceRecord:
        with self._lock:
            sid = _check_id(service_id, "service_id")
            try:
                return self._services[sid]
            except KeyError:
                raise UnknownServiceError(f"unknown service id: {sid!r}")

    def health_of(self, service_id: str) -> str:
        with self._lock:
            sid = _check_id(service_id, "service_id")
            if sid in self._deregistered:
                raise DeregisteredServiceError(
                    f"service id {sid!r} was deregistered and is retired"
                )
            try:
                return self._health[sid]
            except KeyError:
                raise UnknownServiceError(f"unknown service id: {sid!r}")

    def service_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._services))

    def deregistered_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._deregistered))

    def health_reports(self, service_id: str) -> Tuple[HealthReport, ...]:
        with self._lock:
            sid = _check_id(service_id, "service_id")
            try:
                return tuple(self._health_reports[sid])
            except KeyError:
                raise UnknownServiceError(f"unknown service id: {sid!r}")

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "services": len(self._services),
                "deregistered": len(self._deregistered),
                "healthy": sum(1 for h in self._health.values() if h == "healthy"),
                "audit_rows": len(self._audit),
                "last_seq": self._last_seq,
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)

    def as_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "schema": SERVICE_DISCOVERY_SCHEMA,
                "module": SERVICE_DISCOVERY_VERSION,
                "services": {
                    sid: {
                        "service_name": rec.service_name,
                        "address": rec.address,
                        "port": rec.port,
                        "tags": list(rec.tags),
                        "health": self._health[sid],
                        "digest": rec.digest,
                    }
                    for sid, rec in sorted(self._services.items())
                },
                "last_seq": self._last_seq,
            }


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    sd = ServiceDiscovery()
    rec = sd.register("web-1", "web", "10.0.0.1", 1, port=8080, tags=("v2",))
    assert rec.verify()
    rep = sd.report("web-1", True, 2)
    assert rep.verify()
    assert sd.health_of("web-1") == "healthy"
    look = sd.lookup("web", 3)
    assert look.verify() and look.instance_ids == ("web-1",)
    cat = sd.list_services(4)
    assert cat.verify() and cat.service_names == ("web",)
    dr = sd.deregister("web-1", 5, reason="scale-in")
    assert dr.verify()
    print("service-discovery OK: register, report, lookup, deregister, pins, audit")


if __name__ == "__main__":
    main()
