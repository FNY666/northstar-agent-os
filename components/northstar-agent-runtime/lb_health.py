"""Load balancer health: backend registration, probe outcomes, drain/restore.

An ``LBHealth`` ledger books host-reported load-balancer health decisions
as a deterministic single-host state machine:

- ``register_backend(backend_id, address, seq, weight=1)`` pins a backend
  (``host:port`` address, positive weight) into the pool, healthy by
  default until probes say otherwise.
- ``check(backend_id, seq, outcome)`` books one host-reported probe
  outcome (``"healthy"`` / ``"unhealthy"``). Consecutive outcomes move
  the backend's state: ``fail_threshold`` consecutive ``"unhealthy"``
  results flip it to ``"unhealthy"``; ``success_threshold`` consecutive
  ``"healthy"`` results flip it back. States are *data*, never raised.
- ``drain(backend_id, seq, reason)`` removes a backend from rotation
  (no new traffic; existing connections keep draining) until
  ``restore(backend_id, seq)`` returns it.
- ``pool(seq)`` is a pure view returning the currently eligible
  backends (registered, not drained, healthy) with their weights.

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (no wall-clock), RLock-guarded, fail-closed taxonomy, stdlib-only
plus the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, ``audit.ndjson/1`` events, version pin ``lb-health.v1``,
schema pin ``northstar.lb-health.v1``, ``main()`` self-check.

Honest scope: this module books *host-reported* probe outcomes and
drain decisions — it runs no probes, opens no sockets, and cannot prove
a backend is actually reachable or that a drained backend stopped
receiving traffic. Probe outcomes are GIGO: a lying host yields a lying
pool. ``register_backend`` marks the backend healthy by default; the
caller should run at least one probe before relying on the pool.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
LB_HEALTH_VERSION = "lb-health.v1"

#: Schema pin carried by records and audit events.
LB_HEALTH_SCHEMA = "northstar.lb-health.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned probe-outcome vocabulary.
OUTCOMES = ("healthy", "unhealthy")

#: Pinned backend state vocabulary.
STATES = ("healthy", "unhealthy", "draining")

_GENESIS = "genesis"


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class LBHealthError(ValueError):
    """Base for all load-balancer-health structural problems."""


class UnknownBackendError(LBHealthError):
    """No backend is pinned under the requested id."""


class DuplicateBackendError(LBHealthError):
    """A backend id is already registered (ids are never recycled)."""


class BadBackendError(LBHealthError):
    """Backend definition is malformed (bad id, address, or weight)."""


class BadOutcomeError(LBHealthError):
    """Probe outcome is not in the pinned vocabulary."""


class AlreadyDrainedError(LBHealthError):
    """The backend is already drained."""


class NotDrainedError(LBHealthError):
    """The backend is not drained; nothing to restore."""


class SeqOrderError(LBHealthError):
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
        raise LBHealthError(f"{name} must be a non-empty string")
    return value.strip()


def _check_address(value: Any) -> str:
    value = _check_nonempty_str(value, "address")
    if ":" not in value:
        raise BadBackendError("address must look like 'host:port'")
    host, _, port = value.rpartition(":")
    if not host:
        raise BadBackendError("address host part must be non-empty")
    if not port.isdigit() or not (1 <= int(port) <= 65535):
        raise BadBackendError("address port must be a number in 1..65535")
    return value


def _check_weight(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise BadBackendError("weight must be a positive int")
    return value


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        jcs_canonical_json([LB_HEALTH_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BackendRecord:
    """One pinned backend (frozen). Registered healthy by default."""

    backend_id: str
    address: str
    weight: int
    seq: int
    digest: str
    schema: str = LB_HEALTH_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "backend", self.backend_id, self.address, self.weight, self.seq
        )


@dataclass(frozen=True)
class CheckRecord:
    """One booked probe outcome (frozen). State transitions are data."""

    check_id: str
    backend_id: str
    outcome: str
    state: str
    consecutive_healthy: int
    consecutive_unhealthy: int
    seq: int
    digest: str
    schema: str = LB_HEALTH_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "check", self.check_id, self.backend_id, self.outcome,
            self.state, self.consecutive_healthy, self.consecutive_unhealthy,
            self.seq,
        )


@dataclass(frozen=True)
class DrainRecord:
    """One drain decision (frozen). The backend leaves rotation."""

    backend_id: str
    reason: str
    seq: int
    digest: str
    schema: str = LB_HEALTH_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "drain", self.backend_id, self.reason, self.seq
        )


@dataclass(frozen=True)
class RestoreRecord:
    """One restore decision (frozen). The backend rejoins rotation."""

    backend_id: str
    seq: int
    digest: str
    schema: str = LB_HEALTH_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin("restore", self.backend_id, self.seq)


@dataclass(frozen=True)
class PoolReport:
    """One rotation-eligibility snapshot (frozen). Pure view."""

    backends: Tuple[Tuple[str, int], ...]
    seq: int
    digest: str
    schema: str = LB_HEALTH_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "pool", [list(pair) for pair in self.backends], self.seq
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

KIND_BACKEND_REGISTERED = "lb-health.backend-registered"
KIND_CHECKED = "lb-health.checked"
KIND_DRAINED = "lb-health.drained"
KIND_RESTORED = "lb-health.restored"
KIND_REJECTED = "lb-health.rejected"
_KINDS = (
    KIND_BACKEND_REGISTERED, KIND_CHECKED, KIND_DRAINED,
    KIND_RESTORED, KIND_REJECTED,
)


def lb_health_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the lb-health module."""
    if kind not in _KINDS:
        raise LBHealthError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise LBHealthError("detail must be a mapping")
    # Audit carries ids and digest pins only; outcomes live in the ledger.
    banned = {"outcomes", "history"}
    if any(k in detail for k in banned):
        raise LBHealthError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": LB_HEALTH_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class LBHealth:
    """Deterministic load-balancer health ledger.

    All state mutations take a caller-supplied ``seq`` (monotonic
    logical time); no wall-clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position).
    """

    def __init__(self, *, fail_threshold: int = 3, success_threshold: int = 2) -> None:
        for name, value in (("fail_threshold", fail_threshold),
                            ("success_threshold", success_threshold)):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise LBHealthError(f"{name} must be a positive int")
        self._fail_threshold = fail_threshold
        self._success_threshold = success_threshold
        self._lock = threading.RLock()
        self._last_seq = -1
        self._backends: Dict[str, BackendRecord] = {}
        self._states: Dict[str, str] = {}            # backend_id -> health state
        self._consec_healthy: Dict[str, int] = {}
        self._consec_unhealthy: Dict[str, int] = {}
        self._drained: Dict[str, DrainRecord] = {}   # backend_id -> drain record
        self._check_seq = 0
        self._audit: List[Dict[str, Any]] = []

    # -- internals ------------------------------------------------------

    def _claim_seq(self, seq: int) -> int:
        _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} did not strictly increase (last={self._last_seq})"
            )
        self._last_seq = seq
        return seq

    def _audit_locked(self, kind: str, detail: Mapping[str, Any]) -> None:
        self._audit.append(lb_health_audit_event(kind, detail, self._last_seq))

    def _reject_locked(self, reason: str) -> None:
        self._audit_locked(KIND_REJECTED, {"reason": reason})

    # -- backends -------------------------------------------------------

    def register_backend(
        self, backend_id: str, address: str, seq: int, weight: int = 1
    ) -> BackendRecord:
        """Pin a backend into the pool (healthy until probes say otherwise)."""
        with self._lock:
            backend_id = _check_nonempty_str(backend_id, "backend_id")
            address = _check_address(address)
            weight = _check_weight(weight)
            self._claim_seq(seq)
            if backend_id in self._backends:
                self._reject_locked("duplicate-backend")
                raise DuplicateBackendError(
                    f"backend {backend_id!r} already registered"
                )
            record = BackendRecord(
                backend_id=backend_id, address=address, weight=weight,
                seq=seq,
                digest=_pin("backend", backend_id, address, weight, seq),
            )
            self._backends[backend_id] = record
            self._states[backend_id] = "healthy"
            self._consec_healthy[backend_id] = 0
            self._consec_unhealthy[backend_id] = 0
            self._audit_locked(
                KIND_BACKEND_REGISTERED,
                {"backend_id": backend_id, "digest": record.digest},
            )
            return record

    # -- probes ---------------------------------------------------------

    def check(self, backend_id: str, seq: int, outcome: str) -> CheckRecord:
        """Book one host-reported probe outcome; return the new state.

        ``"healthy"`` / ``"unhealthy"`` is the pinned vocabulary.
        ``fail_threshold`` consecutive ``"unhealthy"`` results flip the
        backend to ``"unhealthy"``; ``success_threshold`` consecutive
        ``"healthy"`` results flip it back. A drained backend keeps its
        ``"draining"`` state while counters still accumulate.
        """
        with self._lock:
            backend_id = _check_nonempty_str(backend_id, "backend_id")
            self._claim_seq(seq)
            if backend_id not in self._backends:
                self._reject_locked("unknown-backend")
                raise UnknownBackendError(f"unknown backend {backend_id!r}")
            if outcome not in OUTCOMES:
                self._reject_locked("bad-outcome")
                raise BadOutcomeError(
                    f"outcome must be one of {OUTCOMES}, got {outcome!r}"
                )
            if outcome == "unhealthy":
                self._consec_unhealthy[backend_id] += 1
                self._consec_healthy[backend_id] = 0
            else:
                self._consec_healthy[backend_id] += 1
                self._consec_unhealthy[backend_id] = 0
            current = self._states[backend_id]
            if backend_id in self._drained:
                state = "draining"
            elif self._consec_unhealthy[backend_id] >= self._fail_threshold:
                state = "unhealthy"
            elif self._consec_healthy[backend_id] >= self._success_threshold:
                state = "healthy"
            else:
                state = current
            self._states[backend_id] = state
            self._check_seq += 1
            check_id = f"chk-{self._check_seq}"
            healthy_n = self._consec_healthy[backend_id]
            unhealthy_n = self._consec_unhealthy[backend_id]
            record = CheckRecord(
                check_id=check_id, backend_id=backend_id, outcome=outcome,
                state=state, consecutive_healthy=healthy_n,
                consecutive_unhealthy=unhealthy_n, seq=seq,
                digest=_pin(
                    "check", check_id, backend_id, outcome, state,
                    healthy_n, unhealthy_n, seq,
                ),
            )
            self._audit_locked(
                KIND_CHECKED,
                {
                    "check_id": check_id, "backend_id": backend_id,
                    "state": state, "digest": record.digest,
                },
            )
            return record

    # -- drain / restore ------------------------------------------------

    def drain(self, backend_id: str, seq: int, reason: str) -> DrainRecord:
        """Remove a backend from rotation (existing connections keep going)."""
        with self._lock:
            backend_id = _check_nonempty_str(backend_id, "backend_id")
            reason = _check_nonempty_str(reason, "reason")
            self._claim_seq(seq)
            if backend_id not in self._backends:
                self._reject_locked("unknown-backend")
                raise UnknownBackendError(f"unknown backend {backend_id!r}")
            if backend_id in self._drained:
                self._reject_locked("already-drained")
                raise AlreadyDrainedError(
                    f"backend {backend_id!r} already drained"
                )
            record = DrainRecord(
                backend_id=backend_id, reason=reason, seq=seq,
                digest=_pin("drain", backend_id, reason, seq),
            )
            self._drained[backend_id] = record
            self._states[backend_id] = "draining"
            self._audit_locked(
                KIND_DRAINED,
                {"backend_id": backend_id, "digest": record.digest},
            )
            return record

    def restore(self, backend_id: str, seq: int) -> RestoreRecord:
        """Return a drained backend to rotation at its probe-derived state."""
        with self._lock:
            backend_id = _check_nonempty_str(backend_id, "backend_id")
            self._claim_seq(seq)
            if backend_id not in self._backends:
                self._reject_locked("unknown-backend")
                raise UnknownBackendError(f"unknown backend {backend_id!r}")
            if backend_id not in self._drained:
                self._reject_locked("not-drained")
                raise NotDrainedError(
                    f"backend {backend_id!r} is not drained"
                )
            del self._drained[backend_id]
            # The probe-derived health state decides eligibility again.
            if self._consec_unhealthy[backend_id] >= self._fail_threshold:
                self._states[backend_id] = "unhealthy"
            else:
                self._states[backend_id] = "healthy"
            record = RestoreRecord(
                backend_id=backend_id, seq=seq,
                digest=_pin("restore", backend_id, seq),
            )
            self._audit_locked(
                KIND_RESTORED,
                {"backend_id": backend_id, "digest": record.digest},
            )
            return record

    # -- pool -----------------------------------------------------------

    def pool(self, seq: int) -> PoolReport:
        """Eligible backends: registered, not drained, healthy.

        Pure view: validates ``seq`` shape but does not consume it and
        writes no audit entry.
        """
        with self._lock:
            _check_seq(seq, "seq")
            pairs = tuple(
                sorted(
                    (bid, rec.weight)
                    for bid, rec in self._backends.items()
                    if bid not in self._drained and self._states[bid] == "healthy"
                )
            )
            return PoolReport(
                backends=pairs, seq=seq,
                digest=_pin("pool", [list(p) for p in pairs], seq),
            )

    # -- views ----------------------------------------------------------

    def health_state(self, backend_id: str) -> str:
        with self._lock:
            bid = _check_nonempty_str(backend_id, "backend_id")
            if bid not in self._backends:
                raise UnknownBackendError(f"unknown backend {bid!r}")
            return self._states[bid]

    def backend(self, backend_id: str) -> BackendRecord:
        with self._lock:
            record = self._backends.get(_check_nonempty_str(backend_id, "backend_id"))
            if record is None:
                raise UnknownBackendError(f"unknown backend {backend_id!r}")
            return record

    def backend_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._backends))

    def drained_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._drained))

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    lb = LBHealth()
    b1 = lb.register_backend("web-1", "10.0.0.1:8080", 1, weight=3)
    assert b1.verify()
    b2 = lb.register_backend("web-2", "10.0.0.2:8080", 2)
    assert b2.verify()
    # Pool starts with both.
    p0 = lb.pool(2)
    assert p0.verify() and dict(p0.backends) == {"web-1": 3, "web-2": 1}
    # Three consecutive unhealthy flips web-2 (default fail_threshold=3).
    c1 = lb.check("web-2", 3, "unhealthy")
    c2 = lb.check("web-2", 4, "unhealthy")
    assert lb.health_state("web-2") == "healthy"
    c3 = lb.check("web-2", 5, "unhealthy")
    assert c3.verify() and c3.state == "unhealthy"
    assert lb.health_state("web-2") == "unhealthy"
    p1 = lb.pool(5)
    assert dict(p1.backends) == {"web-1": 3}
    # Two consecutive healthy recovers (default success_threshold=2).
    lb.check("web-2", 6, "healthy")
    assert lb.health_state("web-2") == "unhealthy"
    c4 = lb.check("web-2", 7, "healthy")
    assert c4.state == "healthy"
    # Drain / restore lifecycle.
    d = lb.drain("web-1", 8, "deploys in flight")
    assert d.verify() and lb.health_state("web-1") == "draining"
    assert dict(lb.pool(8).backends) == {"web-2": 1}
    r = lb.restore("web-1", 9)
    assert r.verify() and lb.health_state("web-1") == "healthy"
    assert dict(lb.pool(9).backends) == {"web-1": 3, "web-2": 1}
    # Refusals stay fail-closed (fresh seqs so each hits its own branch).
    lb.drain("web-1", 10, "second drain")
    for bad in (
        lambda: lb.register_backend("web-1", "10.0.0.9:8080", 11),
        lambda: lb.check("nope", 12, "healthy"),
        lambda: lb.check("web-1", 13, "flapping"),
        lambda: lb.drain("web-1", 14, "double drain"),
        lambda: lb.restore("web-2", 15),
    ):
        try:
            bad()
        except LBHealthError:
            pass
        else:
            raise AssertionError("refusal expected")
    print("lb-health OK: register, check, thresholds, drain, restore, pool")
    return None


if __name__ == "__main__":
    main()
