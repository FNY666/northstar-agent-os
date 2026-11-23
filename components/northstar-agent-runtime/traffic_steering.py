"""Traffic steering: geo / latency / weighted routing bookkeeping (simulated).

Interface:
    TrafficSteering.register_origin(origin_id, region, seq, latency_ms=, capacity=)
        -> sealed OriginRecord
    TrafficSteering.set_weight(origin_id, weight, seq) -> sealed WeightRecord
    TrafficSteering.route(request_id, client_region, seq, policy="geo")
        -> sealed RouteDecision (geo | latency | weighted)
    TrafficSteering.probe(origin_id, ok, seq) -> sealed ProbeRecord
        (host-reported health; 3 consecutive failures auto-fail the origin)
    TrafficSteering.failover(origin_id, seq, reason="") -> sealed FailoverRecord
    TrafficSteering.recover(origin_id, seq) -> sealed RecoveryRecord

Routing is deterministic single-host bookkeeping over host-reported data:
origins, latencies and probe outcomes are declared by the host (GIGO
boundary). ``route()`` never selects an unhealthy origin; when no healthy
origin exists it refuses fail-closed (``NoHealthyOriginError``) instead of
guessing. No real DNS, anycast or network I/O happens here.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (failed mutations consume their seq), no wall-clock, RLock-guarded,
fail-closed, stdlib-only, ``sha256:`` digest pins, ``audit.ndjson/1`` events.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, List, Optional, Tuple


_MODULE_VERSION = "traffic-steering.v1"
_SCHEMA_PIN = "northstar.traffic-steering.v1"
_AUDIT_TYPE = "audit.ndjson/1"

# Pinned routing-policy vocabulary.
POLICIES = ("geo", "latency", "weighted")

# Pinned region vocabulary (ISO-ish codes the ledger understands).
REGIONS = (
    "us-east", "us-west", "eu-west", "eu-central", "uk",
    "ap-south", "ap-southeast", "ap-northeast", "sa-east",
    "me-central", "af-south", "oc-sydney",
)

# Probes: consecutive host-reported failures that auto-fail an origin.
_PROBE_FAILOVER_THRESHOLD = 3


class TrafficSteeringError(ValueError):
    """Base for all traffic_steering errors."""


class BadOriginError(TrafficSteeringError):
    """Origin id / region / latency / capacity failed validation."""


class DuplicateOriginError(TrafficSteeringError):
    """An origin with this id is already registered."""


class UnknownOriginError(TrafficSteeringError):
    """Origin id not found."""


class AlreadyFailedOverError(TrafficSteeringError):
    """Origin is already marked unhealthy."""


class NotFailedOverError(TrafficSteeringError):
    """Origin is not marked unhealthy; nothing to recover."""


class BadWeightError(TrafficSteeringError):
    """Weight failed validation (must be int >= 1)."""


class BadPolicyError(TrafficSteeringError):
    """Unknown routing policy."""


class NoHealthyOriginError(TrafficSteeringError):
    """No healthy origin available for routing (fail-closed)."""


class SeqOrderError(TrafficSteeringError):
    """Caller seq did not strictly increase."""


def _reject(reason: str) -> TrafficSteeringError:
    table = {
        "bad-origin": BadOriginError,
        "duplicate": DuplicateOriginError,
        "unknown": UnknownOriginError,
        "already-failed": AlreadyFailedOverError,
        "not-failed": NotFailedOverError,
        "bad-weight": BadWeightError,
        "bad-policy": BadPolicyError,
        "no-healthy": NoHealthyOriginError,
        "seq": SeqOrderError,
    }
    return table.get(reason, TrafficSteeringError)(reason)


def _canonical(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _digest(kind: str, payload: Any) -> str:
    h = hashlib.sha256()
    h.update(kind.encode("utf-8"))
    h.update(b"\x00")
    h.update(_canonical(payload).encode("utf-8"))
    return "sha256:" + h.hexdigest()


def _check_seq_kind(seq: Any) -> None:
    # bool is an int subclass; reject it explicitly (house discipline).
    if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
        raise _reject("seq")


# ---------------------------------------------------------------------------
# Sealed records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OriginRecord:
    origin_id: str
    region: str
    latency_ms: int
    capacity: int
    created_at_seq: int
    digest: str = ""

    def verify_digest(self) -> bool:
        payload = {k: v for k, v in asdict(self).items() if k != "digest"}
        return self.digest == _digest("origin", payload)


@dataclass(frozen=True)
class WeightRecord:
    origin_id: str
    weight: int
    updated_at_seq: int
    digest: str = ""

    def verify_digest(self) -> bool:
        payload = {k: v for k, v in asdict(self).items() if k != "digest"}
        return self.digest == _digest("weight", payload)


@dataclass(frozen=True)
class RouteDecision:
    decision_id: str
    request_id: str
    client_region: str
    policy: str
    origin_id: str
    matched: str  # "region" | "lowest-latency" | "weighted-bucket" | "latency"
    decided_at_seq: int
    digest: str = ""

    def verify_digest(self) -> bool:
        payload = {k: v for k, v in asdict(self).items() if k != "digest"}
        return self.digest == _digest("route-decision", payload)


@dataclass(frozen=True)
class ProbeRecord:
    probe_id: str
    origin_id: str
    ok: bool
    consecutive_failures: int
    probed_at_seq: int
    digest: str = ""

    def verify_digest(self) -> bool:
        payload = {k: v for k, v in asdict(self).items() if k != "digest"}
        return self.digest == _digest("probe", payload)


@dataclass(frozen=True)
class FailoverRecord:
    failover_id: str
    origin_id: str
    reason: str
    automatic: bool
    failed_at_seq: int
    digest: str = ""

    def verify_digest(self) -> bool:
        payload = {k: v for k, v in asdict(self).items() if k != "digest"}
        return self.digest == _digest("failover", payload)


@dataclass(frozen=True)
class RecoveryRecord:
    recovery_id: str
    origin_id: str
    recovered_at_seq: int
    digest: str = ""

    def verify_digest(self) -> bool:
        payload = {k: v for k, v in asdict(self).items() if k != "digest"}
        return self.digest == _digest("recovery", payload)


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class TrafficSteering:
    """Deterministic geo/latency/weighted routing bookkeeping.

    Args:
        audit: caller-supplied ``(event_dict) -> None`` sink for
            ``audit.ndjson/1`` events. Must be callable.
    """

    def __init__(self, audit: Callable[[Dict[str, Any]], None]) -> None:
        if not callable(audit):
            raise TrafficSteeringError("audit must be callable")
        self._audit = audit
        self._lock = threading.RLock()
        self._seq = 0
        self._origin_counter = 0
        self._weight_counter = 0
        self._decision_counter = 0
        self._probe_counter = 0
        self._failover_counter = 0
        self._recovery_counter = 0
        self._origins: Dict[str, OriginRecord] = {}
        self._weights: Dict[str, WeightRecord] = {}
        self._healthy: Dict[str, bool] = {}
        self._failures: Dict[str, int] = {}  # origin_id -> consecutive probe failures
        self._failovers: Dict[str, FailoverRecord] = {}
        self._decisions: Dict[str, RouteDecision] = {}

    # -- internal helpers ----------------------------------------------------

    def _require_seq(self, seq: int) -> None:
        _check_seq_kind(seq)
        if seq <= self._seq:
            raise _reject("seq")
        self._seq = seq

    def _emit(self, kind: str, seq: int, detail: Dict[str, Any]) -> None:
        self._audit(
            {
                "schema_version": _AUDIT_TYPE,
                "component": "northstar-agent-runtime",
                "module": _MODULE_VERSION,
                "event": kind,
                "seq": seq,
                "detail": detail,
            }
        )

    def _fail_locked(self, reason: str, seq: int, why: str = "") -> TrafficSteeringError:
        # Failed mutations consume their seq (batch discipline).
        self._require_seq(seq)
        self._emit("rejected", seq, {"reason": reason, "why": why})
        return _reject(reason)

    def _healthy_origins(self) -> List[OriginRecord]:
        return [o for o in sorted(self._origins.values(), key=lambda r: r.origin_id)
                if self._healthy.get(o.origin_id, False)]

    # -- public API ----------------------------------------------------------

    def register_origin(
        self,
        origin_id: Any,
        region: Any,
        seq: int,
        latency_ms: int = 50,
        capacity: int = 100,
    ) -> OriginRecord:
        with self._lock:
            if (
                not isinstance(origin_id, str) or not origin_id
                or not isinstance(region, str) or region not in REGIONS
                or isinstance(latency_ms, bool) or not isinstance(latency_ms, int)
                or latency_ms < 0
                or isinstance(capacity, bool) or not isinstance(capacity, int)
                or capacity <= 0
            ):
                raise self._fail_locked("bad-origin", seq, "origin fields invalid")
            if origin_id in self._origins:
                raise self._fail_locked("duplicate", seq, "origin id taken")
            self._require_seq(seq)
            self._origin_counter += 1
            rec = OriginRecord(
                origin_id=origin_id,
                region=region,
                latency_ms=latency_ms,
                capacity=capacity,
                created_at_seq=seq,
            )
            rec = self._pin_origin(rec)
            self._origins[origin_id] = rec
            self._healthy[origin_id] = True
            self._failures[origin_id] = 0
            # Default weight 1 so weighted routing works out of the box.
            self._weights[origin_id] = self._pin_weight(
                WeightRecord(origin_id=origin_id, weight=1, updated_at_seq=seq)
            )
            self._emit("origin-registered", seq,
                       {"origin_id": origin_id, "region": region,
                        "digest": rec.digest})
            return rec

    @staticmethod
    def _pin_origin(rec: OriginRecord) -> OriginRecord:
        payload = {k: v for k, v in asdict(rec).items() if k != "digest"}
        return OriginRecord(**{**payload, "digest": _digest("origin", payload)})

    @staticmethod
    def _pin_weight(rec: WeightRecord) -> WeightRecord:
        payload = {k: v for k, v in asdict(rec).items() if k != "digest"}
        return WeightRecord(**{**payload, "digest": _digest("weight", payload)})

    def set_weight(self, origin_id: Any, weight: Any, seq: int) -> WeightRecord:
        with self._lock:
            if origin_id not in self._origins:
                raise self._fail_locked("unknown", seq, "origin not found")
            if isinstance(weight, bool) or not isinstance(weight, int) or weight < 1:
                raise self._fail_locked("bad-weight", seq, "weight must be int >= 1")
            self._require_seq(seq)
            self._weight_counter += 1
            rec = self._pin_weight(
                WeightRecord(origin_id=origin_id, weight=weight, updated_at_seq=seq)
            )
            self._weights[origin_id] = rec
            self._emit("weight-set", seq,
                       {"origin_id": origin_id, "weight": weight,
                        "digest": rec.digest})
            return rec

    def route(
        self,
        request_id: Any,
        client_region: Any,
        seq: int,
        policy: str = "geo",
    ) -> RouteDecision:
        with self._lock:
            _check_seq_kind(seq)  # read view: validate shape, do not consume
            if policy not in POLICIES:
                raise self._fail_locked("bad-policy", seq, "unknown policy")
            if not isinstance(request_id, str) or not request_id:
                raise self._fail_locked("bad-origin", seq, "request_id must be non-empty str")
            if not isinstance(client_region, str) or client_region not in REGIONS:
                raise self._fail_locked("bad-origin", seq, "unknown client region")
            healthy = self._healthy_origins()
            if not healthy:
                raise self._fail_locked("no-healthy", seq, "all origins unhealthy")

            if policy == "geo":
                same = [o for o in healthy if o.region == client_region]
                if same:
                    chosen, matched = same[0], "region"
                else:
                    chosen = min(healthy, key=lambda o: (o.latency_ms, o.origin_id))
                    matched = "lowest-latency"
            elif policy == "latency":
                chosen = min(healthy, key=lambda o: (o.latency_ms, o.origin_id))
                matched = "latency"
            else:  # weighted
                total = sum(self._weights[o.origin_id].weight for o in healthy)
                bucket = int(hashlib.sha256(
                    ("weighted|" + request_id).encode("utf-8")).hexdigest(), 16) % total
                acc = 0
                chosen = healthy[-1]
                for o in healthy:
                    acc += self._weights[o.origin_id].weight
                    if bucket < acc:
                        chosen = o
                        break
                matched = "weighted-bucket"

            self._decision_counter += 1
            dec = RouteDecision(
                decision_id=f"dec-{self._decision_counter}",
                request_id=request_id,
                client_region=client_region,
                policy=policy,
                origin_id=chosen.origin_id,
                matched=matched,
                decided_at_seq=seq,
            )
            payload = {k: v for k, v in asdict(dec).items() if k != "digest"}
            dec = RouteDecision(**{**payload, "digest": _digest("route-decision", payload)})
            self._decisions[dec.decision_id] = dec
            self._emit("routed", seq,
                       {"decision_id": dec.decision_id, "origin_id": chosen.origin_id,
                        "policy": policy, "matched": matched, "digest": dec.digest})
            return dec

    def probe(self, origin_id: Any, ok: Any, seq: int) -> ProbeRecord:
        with self._lock:
            if origin_id not in self._origins:
                raise self._fail_locked("unknown", seq, "origin not found")
            if not isinstance(ok, bool):
                raise self._fail_locked("bad-origin", seq, "ok must be bool")
            self._require_seq(seq)
            self._probe_counter += 1
            if ok:
                self._failures[origin_id] = 0
            else:
                self._failures[origin_id] = self._failures.get(origin_id, 0) + 1
            consecutive = self._failures[origin_id]
            rec = ProbeRecord(
                probe_id=f"prb-{self._probe_counter}",
                origin_id=origin_id,
                ok=ok,
                consecutive_failures=consecutive,
                probed_at_seq=seq,
            )
            payload = {k: v for k, v in asdict(rec).items() if k != "digest"}
            rec = ProbeRecord(**{**payload, "digest": _digest("probe", payload)})
            self._emit("probed", seq,
                       {"probe_id": rec.probe_id, "origin_id": origin_id,
                        "ok": ok, "consecutive_failures": consecutive,
                        "digest": rec.digest})
            # Auto-failover on sustained host-reported failure.
            if (not ok and consecutive >= _PROBE_FAILOVER_THRESHOLD
                    and self._healthy.get(origin_id, False)):
                self._fail_locked_origin(origin_id, seq, automatic=True,
                                         reason="auto:probe-threshold")
            return rec

    def _fail_locked_origin(self, origin_id: str, seq: int,
                            automatic: bool, reason: str) -> FailoverRecord:
        self._failover_counter += 1
        self._healthy[origin_id] = False
        rec = FailoverRecord(
            failover_id=f"fo-{self._failover_counter}",
            origin_id=origin_id,
            reason=reason,
            automatic=automatic,
            failed_at_seq=seq,
        )
        payload = {k: v for k, v in asdict(rec).items() if k != "digest"}
        rec = FailoverRecord(**{**payload, "digest": _digest("failover", payload)})
        self._failovers[rec.failover_id] = rec
        self._emit("failed-over", seq,
                   {"failover_id": rec.failover_id, "origin_id": origin_id,
                    "automatic": automatic, "digest": rec.digest})
        return rec

    def failover(self, origin_id: Any, seq: int, reason: str = "") -> FailoverRecord:
        with self._lock:
            if origin_id not in self._origins:
                raise self._fail_locked("unknown", seq, "origin not found")
            if not self._healthy.get(origin_id, False):
                raise self._fail_locked("already-failed", seq, "already unhealthy")
            if not isinstance(reason, str):
                raise self._fail_locked("bad-origin", seq, "reason must be str")
            self._require_seq(seq)
            return self._fail_locked_origin(origin_id, seq, automatic=False,
                                            reason=reason)

    def recover(self, origin_id: Any, seq: int) -> RecoveryRecord:
        with self._lock:
            if origin_id not in self._origins:
                raise self._fail_locked("unknown", seq, "origin not found")
            if self._healthy.get(origin_id, False):
                raise self._fail_locked("not-failed", seq, "origin is healthy")
            self._require_seq(seq)
            self._recovery_counter += 1
            self._healthy[origin_id] = True
            self._failures[origin_id] = 0
            rec = RecoveryRecord(
                recovery_id=f"rec-{self._recovery_counter}",
                origin_id=origin_id,
                recovered_at_seq=seq,
            )
            payload = {k: v for k, v in asdict(rec).items() if k != "digest"}
            rec = RecoveryRecord(**{**payload, "digest": _digest("recovery", payload)})
            self._emit("recovered", seq,
                       {"recovery_id": rec.recovery_id, "origin_id": origin_id,
                        "digest": rec.digest})
            return rec

    # -- views ---------------------------------------------------------------

    def origin(self, origin_id: str) -> OriginRecord:
        with self._lock:
            try:
                return self._origins[origin_id]
            except KeyError:
                raise UnknownOriginError("unknown")

    def origin_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._origins))

    def is_healthy(self, origin_id: str) -> bool:
        with self._lock:
            if origin_id not in self._origins:
                raise UnknownOriginError("unknown")
            return self._healthy.get(origin_id, False)

    def weight_of(self, origin_id: str) -> int:
        with self._lock:
            if origin_id not in self._origins:
                raise UnknownOriginError("unknown")
            return self._weights[origin_id].weight

    def decision(self, decision_id: str) -> RouteDecision:
        with self._lock:
            try:
                return self._decisions[decision_id]
            except KeyError:
                raise TrafficSteeringError("unknown decision")


def traffic_steering_audit_event(
    kind: str, seq: int, detail: Dict[str, Any]
) -> Dict[str, Any]:
    allowed = {
        "origin-registered", "weight-set", "routed", "probed",
        "failed-over", "recovered", "rejected",
    }
    if kind not in allowed:
        raise TrafficSteeringError(f"unknown audit kind: {kind!r}")
    return {
        "schema_version": _AUDIT_TYPE,
        "component": "northstar-agent-runtime",
        "module": _MODULE_VERSION,
        "event": kind,
        "seq": seq,
        "detail": detail,
    }


def _stdlib_only_ok(path: str) -> Tuple[bool, str]:
    import ast

    allowed = {
        "hashlib", "json", "threading", "dataclasses", "typing",
        "__future__", "ast",
    }
    with open(path, "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), path)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False, f"import {a.name}"
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False, f"from {node.module} import"
    return True, ""


def main() -> int:
    events: List[Dict[str, Any]] = []
    ts = TrafficSteering(audit=events.append)
    o1 = ts.register_origin("edge-a", "us-east", 1, latency_ms=20)
    assert o1.verify_digest()
    ts.register_origin("edge-b", "eu-west", 2, latency_ms=80)
    d = ts.route("req-1", "us-east", 3, policy="geo")
    assert d.verify_digest() and d.origin_id == "edge-a" and d.matched == "region"
    ts.set_weight("edge-b", 5, 4)
    ts.failover("edge-a", 5, reason="maintenance")
    d2 = ts.route("req-2", "us-east", 6, policy="geo")
    assert d2.origin_id == "edge-b" and d2.matched == "lowest-latency"
    ts.recover("edge-a", 7)
    # auto-failover after 3 bad probes
    ts.probe("edge-a", False, 8)
    ts.probe("edge-a", False, 9)
    ts.probe("edge-a", False, 10)
    assert not ts.is_healthy("edge-a")
    print("traffic-steering OK: register, route, weight, failover, probe, recover")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
