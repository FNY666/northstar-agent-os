"""Service mesh: Istio-style sidecar registry, routing, and traffic policies.

Research note: a service mesh (Istio, Linkerd) inserts a sidecar proxy
next to every workload and centralizes the traffic plane: service
discovery, load balancing, mutual TLS, authorization, retries, and
fault injection become *declared* policy instead of per-service code.
This module is the *decision bookkeeping* for that idea inside
Northstar: which services are registered, where their endpoints are,
what traffic rules apply, and which endpoint a given call routes to.

* **Registry** — :meth:`ServiceMesh.register` records a service's
  sidecar endpoints (``host:port`` list) as a frozen, digest-pinned
  :class:`ServiceRecord`. Re-registration updates endpoints; the digest
  changes so drift is observable.
* **Traffic policies** — :meth:`ServiceMesh.policy` attaches a frozen
  :class:`TrafficPolicy` to a service: mutual-TLS mode
  (``DISABLED`` / ``PERMISSIVE`` / ``STRICT``), authorization rules
  (allow/deny source service ids), timeout and retry budgets, and
  weighted destination subsets. A policy is *pinned*, never silently
  mutated.
* **Routing** — :meth:`ServiceMesh.route` computes a deterministic
  weighted round-robin endpoint choice for ``src -> dst`` and evaluates
  the destination's authorization rules first. Denied calls return a
  frozen :class:`RouteDecision` with ``allowed=False`` instead of an
  endpoint; the denial is audit-visible.
* **Determinism** — the round-robin cursor advances per destination,
  so identical call sequences replay to identical routing. No
  wall-clock, no RNG: callers supply integer seqs.

House style: frozen dataclasses, version pin ``service-mesh.v1``,
schema pin ``northstar.service-mesh.v1``, fail-closed validation
(bool/empty/malformed inputs all raise), stdlib-only
(``hashlib``, ``hmac``, ``json``, ``threading``, ``dataclasses``),
:func:`service_mesh_audit_event` shapes ``audit.ndjson/1`` records,
and a ``main()`` self-check.

Honest scope: this is *routing-decision bookkeeping*, not a proxy —
there is no socket, no packet, no real TLS handshake, and a route
decision cannot prove the packet arrived or that the peer's identity
was actually attested. Host-reported endpoints are pinned, not
verified: a lying registry entry routes to the liar. mTLS modes are
*recorded intent*; enforcement lives in the sidecar this module does
not implement. Pair with :mod:`remote_attestation` when attested
identity actually matters.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Optional, Sequence

#: Module version.
SERVICE_MESH_VERSION = "service-mesh.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.service-mesh.v1"

#: Audit kinds emitted by :func:`service_mesh_audit_event`.
AUDIT_KINDS = (
    "service-registered",
    "service-updated",
    "policy-set",
    "routed",
    "route-denied",
    "rejected",
)

#: Hard cap on endpoints per service (fail-closed guardrail).
MAX_ENDPOINTS = 64

#: Hard cap on subset weights (weights are small ints).
MAX_WEIGHT = 1_000_000


class ServiceMeshError(Exception):
    """Base class for service-mesh failures."""


class UnknownServiceError(ServiceMeshError):
    """Routing/policy request named a service that is not registered."""


class DuplicateEndpointError(ServiceMeshError):
    """Registration carried duplicate endpoint entries."""


class AuthorizationError(ServiceMeshError):
    """The destination's policy denied this route (recorded, not raised by route())."""


class MtlsMode(str, Enum):
    """Mutual-TLS posture recorded for a service."""

    DISABLED = "disabled"
    PERMISSIVE = "permissive"
    STRICT = "strict"


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ServiceMeshError(f"seq must be a non-negative int, got {seq!r}")
    return seq


def _check_service_id(service_id: Any) -> str:
    if not isinstance(service_id, str) or not service_id.strip():
        raise ServiceMeshError(f"service_id must be a non-empty str, got {service_id!r}")
    if len(service_id) > 256:
        raise ServiceMeshError("service_id too long (max 256)")
    return service_id.strip()


def _check_endpoint(endpoint: Any) -> str:
    if not isinstance(endpoint, str) or not endpoint.strip():
        raise ServiceMeshError(f"endpoint must be a non-empty str, got {endpoint!r}")
    ep = endpoint.strip()
    if ":" not in ep:
        raise ServiceMeshError(f"endpoint must be host:port, got {ep!r}")
    host, _, port = ep.rpartition(":")
    if not host or not port.isdigit() or not (1 <= int(port) <= 65535):
        raise ServiceMeshError(f"endpoint must be host:port with valid port, got {ep!r}")
    return ep


def _canonical(value: Any) -> bytes:
    """Type-tagged canonical encoding (bool != int; NaN/inf refused)."""

    def enc(v: Any) -> Any:
        if isinstance(v, bool):
            return {"__bool__": v}
        if isinstance(v, int):
            if abs(v) > 2**53:
                raise ServiceMeshError(f"int exceeds 2^53 digest-safety bound: {v!r}")
            return {"__int__": v}
        if isinstance(v, float):
            if not math.isfinite(v):
                raise ServiceMeshError(f"non-finite float refused: {v!r}")
            if v.is_integer() and abs(v) > 2**53:
                raise ServiceMeshError(f"float exceeds 2^53 digest-safety bound: {v!r}")
            return {"__float__": repr(v)}
        if isinstance(v, str):
            return {"__str__": v}
        if v is None:
            return {"__null__": True}
        if isinstance(v, (list, tuple)):
            return {"__list__": [enc(i) for i in v]}
        if isinstance(v, Mapping):
            return {"__map__": [[enc(k), enc(vv)] for k, vv in sorted(v.items(), key=lambda kv: str(kv[0]))]}
        raise ServiceMeshError(f"value not canonicalizable: {type(v).__name__}")

    return json.dumps(enc(value), sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(body: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(body)).hexdigest()


@dataclass(frozen=True)
class ServiceRecord:
    """Frozen registration of one service's sidecar endpoints."""

    service_id: str
    endpoints: tuple[str, ...]
    seq: int
    digest: str
    version: str = SERVICE_MESH_VERSION
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if self.version != SERVICE_MESH_VERSION or self.schema != SCHEMA_PIN:
            raise ServiceMeshError("version/schema pin mismatch")

    def as_dict(self) -> dict[str, Any]:
        return {
            "service_id": self.service_id,
            "endpoints": list(self.endpoints),
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class AuthorizationRule:
    """One allow/deny rule evaluated against the *source* service id."""

    action: str  # "allow" or "deny"
    sources: tuple[str, ...]  # source service ids this rule applies to

    def __post_init__(self) -> None:
        if self.action not in ("allow", "deny"):
            raise ServiceMeshError(f"rule action must be allow/deny, got {self.action!r}")
        if not self.sources:
            raise ServiceMeshError("authorization rule needs at least one source")
        for s in self.sources:
            _check_service_id(s)


@dataclass(frozen=True)
class TrafficPolicy:
    """Frozen traffic policy attached to a destination service."""

    service_id: str
    mtls: MtlsMode
    rules: tuple[AuthorizationRule, ...]
    timeout_ms: int
    max_retries: int
    weights: tuple[tuple[str, int], ...]  # (endpoint, weight); empty = uniform
    seq: int
    digest: str
    version: str = SERVICE_MESH_VERSION
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if self.version != SERVICE_MESH_VERSION or self.schema != SCHEMA_PIN:
            raise ServiceMeshError("version/schema pin mismatch")
        if self.timeout_ms < 0 or isinstance(self.timeout_ms, bool):
            raise ServiceMeshError("timeout_ms must be a non-negative int")
        if self.max_retries < 0 or isinstance(self.max_retries, bool):
            raise ServiceMeshError("max_retries must be a non-negative int")

    def as_dict(self) -> dict[str, Any]:
        return {
            "service_id": self.service_id,
            "mtls": self.mtls.value,
            "rules": [
                {"action": r.action, "sources": list(r.sources)} for r in self.rules
            ],
            "timeout_ms": self.timeout_ms,
            "max_retries": self.max_retries,
            "weights": [[ep, w] for ep, w in self.weights],
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }

    def allows(self, src_service_id: str) -> bool:
        """Evaluate authorization rules; first matching rule wins, default allow."""
        for rule in self.rules:
            if src_service_id in rule.sources:
                return rule.action == "allow"
        return True


@dataclass(frozen=True)
class RouteDecision:
    """Frozen outcome of one routing decision."""

    src: str
    dst: str
    endpoint: Optional[str]  # None when denied
    allowed: bool
    mtls: str
    cursor: int  # round-robin position used, -1 when denied
    seq: int
    digest: str
    version: str = SERVICE_MESH_VERSION
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if self.version != SERVICE_MESH_VERSION or self.schema != SCHEMA_PIN:
            raise ServiceMeshError("version/schema pin mismatch")

    def as_dict(self) -> dict[str, Any]:
        return {
            "src": self.src,
            "dst": self.dst,
            "endpoint": self.endpoint,
            "allowed": self.allowed,
            "mtls": self.mtls,
            "cursor": self.cursor,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


class ServiceMesh:
    """Istio-style sidecar registry, policy store, and routing bookkeeping."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._services: dict[str, ServiceRecord] = {}
        self._policies: dict[str, TrafficPolicy] = {}
        self._cursors: dict[str, int] = {}  # dst -> round-robin cursor

    # -- registration -----------------------------------------------------

    def register(
        self,
        service_id: Any,
        endpoints: Sequence[Any],
        seq: Any,
    ) -> ServiceRecord:
        """Register (or update) a service's sidecar endpoints."""
        sid = _check_service_id(service_id)
        seq = _check_seq(seq)
        if not isinstance(endpoints, (list, tuple)) or not endpoints:
            raise ServiceMeshError("endpoints must be a non-empty list/tuple")
        if len(endpoints) > MAX_ENDPOINTS:
            raise ServiceMeshError(f"too many endpoints (max {MAX_ENDPOINTS})")
        eps = tuple(_check_endpoint(e) for e in endpoints)
        if len(set(eps)) != len(eps):
            raise DuplicateEndpointError(f"duplicate endpoints for {sid!r}")
        digest = _digest(("service", sid, eps, seq))
        record = ServiceRecord(
            service_id=sid, endpoints=eps, seq=seq, digest=digest
        )
        with self._lock:
            self._services[sid] = record
            self._cursors.setdefault(sid, 0)
        return record

    def get(self, service_id: Any) -> ServiceRecord:
        sid = _check_service_id(service_id)
        with self._lock:
            try:
                return self._services[sid]
            except KeyError:
                raise UnknownServiceError(f"unknown service: {sid!r}") from None

    def services(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._services))

    def deregister(self, service_id: Any, seq: Any) -> bool:
        """Remove a service and its policy; returns True when something was removed."""
        sid = _check_service_id(service_id)
        _check_seq(seq)
        with self._lock:
            removed = self._services.pop(sid, None) is not None
            self._policies.pop(sid, None)
            self._cursors.pop(sid, None)
            return removed

    # -- policies ----------------------------------------------------------

    def policy(
        self,
        service_id: Any,
        seq: Any,
        *,
        mtls: Any = MtlsMode.DISABLED,
        rules: Sequence[Mapping[str, Any]] | Sequence[AuthorizationRule] = (),
        timeout_ms: Any = 0,
        max_retries: Any = 0,
        weights: Optional[Mapping[str, Any]] = None,
    ) -> TrafficPolicy:
        """Attach a traffic policy to a registered service."""
        sid = _check_service_id(service_id)
        seq = _check_seq(seq)
        with self._lock:
            record = self._services.get(sid)
        if record is None:
            raise UnknownServiceError(f"unknown service: {sid!r}")

        if isinstance(mtls, str):
            try:
                mtls = MtlsMode(mtls)
            except ValueError:
                raise ServiceMeshError(
                    f"mtls must be one of {[m.value for m in MtlsMode]}, got {mtls!r}"
                ) from None
        if not isinstance(mtls, MtlsMode):
            raise ServiceMeshError(f"mtls must be a MtlsMode, got {mtls!r}")

        frozen_rules: list[AuthorizationRule] = []
        for r in rules:
            if isinstance(r, AuthorizationRule):
                frozen_rules.append(r)
            elif isinstance(r, Mapping):
                action = r.get("action")
                sources = r.get("sources")
                if not isinstance(sources, (list, tuple)):
                    raise ServiceMeshError("rule sources must be a list/tuple")
                frozen_rules.append(
                    AuthorizationRule(
                        action=action, sources=tuple(_check_service_id(s) for s in sources)
                    )
                )
            else:
                raise ServiceMeshError(f"rule must be a mapping or AuthorizationRule, got {r!r}")

        frozen_weights: tuple[tuple[str, int], ...] = ()
        if weights is not None:
            if not isinstance(weights, Mapping) or not weights:
                raise ServiceMeshError("weights must be a non-empty mapping")
            items = []
            for ep, w in weights.items():
                ep = _check_endpoint(ep)
                if isinstance(w, bool) or not isinstance(w, int) or w <= 0 or w > MAX_WEIGHT:
                    raise ServiceMeshError(f"weight must be a positive int <= {MAX_WEIGHT}, got {w!r}")
                if ep not in record.endpoints:
                    raise ServiceMeshError(f"weight for unregistered endpoint {ep!r}")
                items.append((ep, w))
            frozen_weights = tuple(sorted(items))

        if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) or timeout_ms < 0:
            raise ServiceMeshError("timeout_ms must be a non-negative int")
        if isinstance(max_retries, bool) or not isinstance(max_retries, int) or max_retries < 0:
            raise ServiceMeshError("max_retries must be a non-negative int")

        digest = _digest(
            ("policy", sid, mtls.value,
             tuple((r.action, r.sources) for r in frozen_rules),
             timeout_ms, max_retries, frozen_weights, seq)
        )
        pol = TrafficPolicy(
            service_id=sid,
            mtls=mtls,
            rules=tuple(frozen_rules),
            timeout_ms=timeout_ms,
            max_retries=max_retries,
            weights=frozen_weights,
            seq=seq,
            digest=digest,
        )
        with self._lock:
            self._policies[sid] = pol
        return pol

    def get_policy(self, service_id: Any) -> TrafficPolicy:
        sid = _check_service_id(service_id)
        with self._lock:
            try:
                return self._policies[sid]
            except KeyError:
                raise UnknownServiceError(f"no policy for service: {sid!r}") from None

    # -- routing -----------------------------------------------------------

    def _pick_endpoint(self, record: ServiceRecord, pol: Optional[TrafficPolicy]) -> tuple[str, int]:
        with self._lock:
            cursor = self._cursors.get(record.service_id, 0)
        if pol is not None and pol.weights:
            weighted: list[str] = []
            for ep, w in pol.weights:
                weighted.extend([ep] * w)
            choice = weighted[cursor % len(weighted)]
        else:
            choice = record.endpoints[cursor % len(record.endpoints)]
        with self._lock:
            self._cursors[record.service_id] = cursor + 1
        return choice, cursor

    def route(
        self,
        src_service_id: Any,
        dst_service_id: Any,
        seq: Any,
    ) -> RouteDecision:
        """Compute a routing decision for ``src -> dst``.

        Authorization rules are evaluated first; a denied call returns
        a frozen ``RouteDecision`` with ``allowed=False`` (never raises
        :class:`AuthorizationError` — denials are data, not control
        flow).
        """
        src = _check_service_id(src_service_id)
        dst = _check_service_id(dst_service_id)
        seq = _check_seq(seq)
        with self._lock:
            record = self._services.get(dst)
            pol = self._policies.get(dst)
        if record is None:
            raise UnknownServiceError(f"unknown service: {dst!r}")
        mtls = pol.mtls.value if pol is not None else MtlsMode.DISABLED.value
        if pol is not None and not pol.allows(src):
            digest = _digest(("route", src, dst, "denied", seq))
            return RouteDecision(
                src=src, dst=dst, endpoint=None, allowed=False,
                mtls=mtls, cursor=-1, seq=seq, digest=digest,
            )
        endpoint, cursor = self._pick_endpoint(record, pol)
        digest = _digest(("route", src, dst, endpoint, cursor, seq))
        return RouteDecision(
            src=src, dst=dst, endpoint=endpoint, allowed=True,
            mtls=mtls, cursor=cursor, seq=seq, digest=digest,
        )

    # -- task API (inject / mtls / traffic) -----------------------------------

    def inject(
        self,
        service_id: Any,
        endpoints: Sequence[Any],
        seq: Any,
    ) -> ServiceRecord:
        """Pin a sidecar proxy onto a service.

        Alias for :meth:`register`: "injection" here is decision
        bookkeeping — the service's sidecar endpoints are registered
        and digest-pinned. No proxy is actually deployed; see the
        module's honest-scope note.
        """
        return self.register(service_id, endpoints, seq)

    def mtls(
        self,
        service_id: Any,
        seq: Any,
        mode: Any = MtlsMode.STRICT,
    ) -> TrafficPolicy:
        """Pin the declared mTLS mode for a service.

        Implemented over :meth:`policy`: existing authorization rules,
        timeouts, retries, and endpoint weights are preserved — only
        the mTLS mode is replaced. Simulated intent, not a handshake.
        """
        try:
            existing = self.get_policy(service_id)
        except UnknownServiceError:
            return self.policy(service_id, seq, mtls=mode)
        weights = dict(existing.weights) if existing.weights else None
        return self.policy(
            service_id,
            seq,
            mtls=mode,
            rules=existing.rules,
            timeout_ms=existing.timeout_ms,
            max_retries=existing.max_retries,
            weights=weights,
        )

    def traffic(
        self,
        src_service_id: Any,
        dst_service_id: Any,
        seq: Any,
    ) -> RouteDecision:
        """Compute a traffic decision for ``src -> dst``.

        Alias for :meth:`route`: authorization is evaluated first and
        denials are returned as data (``allowed=False``), never raised.
        Simulated decision, not a packet.
        """
        return self.route(src_service_id, dst_service_id, seq)


def service_mesh_audit_event(
    kind: str,
    seq: Any,
    record: Any = None,
    detail: str = "",
) -> dict[str, Any]:
    """Shape a mesh event as an ``audit.ndjson/1``-style record."""
    if kind not in AUDIT_KINDS:
        raise ServiceMeshError(f"unknown audit kind: {kind!r}")
    seq = _check_seq(seq)
    if not isinstance(detail, str):
        raise ServiceMeshError("detail must be a str")
    event: dict[str, Any] = {
        "event": f"service-mesh.{kind}",
        "audit_seq": seq,
        "version": SERVICE_MESH_VERSION,
        "schema": SCHEMA_PIN,
        "detail": detail,
    }
    if record is not None:
        if hasattr(record, "as_dict"):
            event["record"] = record.as_dict()
        else:
            raise ServiceMeshError("record must expose as_dict()")
    return event


def main() -> None:
    """Self-check: register, policy, authz deny, weighted round-robin."""
    mesh = ServiceMesh()
    rec = mesh.register("checkout", ["10.0.0.1:8080", "10.0.0.2:8080"], seq=1)
    assert rec.service_id == "checkout" and len(rec.endpoints) == 2
    assert rec.digest.startswith("sha256:") and rec.digest == _digest(
        ("service", "checkout", ("10.0.0.1:8080", "10.0.0.2:8080"), 1)
    )

    pol = mesh.policy(
        "checkout",
        2,
        mtls="strict",
        rules=[{"action": "deny", "sources": ["evil-svc"]}],
        timeout_ms=500,
        max_retries=2,
    )
    assert pol.mtls is MtlsMode.STRICT and not pol.allows("evil-svc")
    assert pol.allows("web")

    denied = mesh.route("evil-svc", "checkout", 3)
    assert not denied.allowed and denied.endpoint is None and denied.cursor == -1

    ok1 = mesh.route("web", "checkout", 4)
    ok2 = mesh.route("web", "checkout", 5)
    assert ok1.allowed and ok1.mtls == "strict"
    assert ok1.endpoint == "10.0.0.1:8080" and ok2.endpoint == "10.0.0.2:8080"

    weighted = mesh.register("api", ["h1:80", "h2:80"], seq=6)
    mesh.policy("api", 7, weights={"h1:80": 2, "h2:80": 1})
    picks = [mesh.route("web", "api", 8 + i).endpoint for i in range(6)]
    assert picks == ["h1:80", "h1:80", "h2:80"] * 2, picks
    assert weighted

    try:
        mesh.route("web", "nope", 20)
    except UnknownServiceError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected UnknownServiceError")

    try:
        mesh.register("bad", ["not-an-endpoint"], 21)
    except ServiceMeshError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected ServiceMeshError")

    ev = service_mesh_audit_event("routed", 22, ok1, detail="web->checkout")
    assert ev["event"] == "service-mesh.routed" and ev["audit_seq"] == 22
    try:
        service_mesh_audit_event("bogus", 23)
    except ServiceMeshError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected ServiceMeshError")

    print("service-mesh OK: register, policy, authz deny, weighted round-robin, audit")


if __name__ == "__main__":
    main()
