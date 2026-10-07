"""Canary deployment controller: deterministic traffic splitting for safe rollout.

Research note: canary deployments are a standard resilience/rollout pattern
(Nygard, *Release It!*; SRE practice) — a new version receives a small
fraction of traffic first, so a bad release fails small before it fails
everywhere. For an agent runtime the same idea applies to model/tool
version rollouts: the host can expose a new agent build to e.g. 1% of
requests, watch the audit trail, and promote or roll back.

* **Deterministic routing** — ``route`` hashes the request id (caller-
  supplied) with the module version pin and takes a draw in ``[0, 100)``.
  A request with ``draw < traffic_pct`` is served by the canary, the rest
  by the stable version. Same request id always routes the same way:
  replayable, no RNG, no wall-clock.
* **One canary at a time** — deploying a second canary while one is live
  is refused (fail closed); the host must promote or roll back first.
* **Fail-closed** — ``promote``/``rollback`` with no live canary raises
  ``CanaryError``; malformed inputs raise, they are never silently
  routed to stable.

Honest scope: this is the *routing decision*, not the rollout verdict —
it cannot see whether the canary is behaving well (error-rate or audit
analysis is the host's job), and a ``stable`` decision means "not in the
canary slice", never "the request is safe". The hash is traffic shaping,
not a security boundary: a caller that knows the scheme can choose
which slice it lands in.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Mapping

#: Module version.
CANARY_CONTROLLER_VERSION = "canary-controller.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.canary-controller.v1"


class CanaryError(Exception):
    """Raised for structural misuse of the controller (no live canary, duplicate deploy)."""


def _check_version_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise TypeError(f"{field_name} must be a non-empty str")
    return value


def _check_pct(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("traffic_pct must be a real number in [0, 100]")
    pct = float(value)
    if pct != pct or pct == float("inf") or pct == float("-inf"):
        raise ValueError("traffic_pct must be finite")
    if pct < 0.0 or pct > 100.0:
        raise ValueError("traffic_pct must be within [0, 100]")
    return pct


def _request_id_of(request: Any) -> str:
    if isinstance(request, str):
        request_id = request
    elif isinstance(request, Mapping):
        request_id = request.get("request_id")
    else:
        raise TypeError("request must be a str or a mapping with 'request_id'")
    if not isinstance(request_id, str) or not request_id:
        raise TypeError("request_id must be a non-empty str")
    return request_id


def _draw(request_id: str) -> float:
    """Deterministic draw in [0, 100) for a request id."""
    digest = hashlib.sha256(
        (CANARY_CONTROLLER_VERSION + "\x00" + request_id).encode("utf-8")
    ).digest()
    # Use 48 bits of the digest; 2**48 / 10000 keeps sub-0.01% resolution.
    value = int.from_bytes(digest[:6], "big")
    return (value % 10_000_000) / 100_000.0


@dataclass(frozen=True)
class Canary:
    """A live canary release: version plus the traffic percentage it serves."""

    version: str
    traffic_pct: float

    def __post_init__(self) -> None:
        _check_version_text(self.version, "version")
        # Re-validate so a bypassed constructor path still fails closed.
        object.__setattr__(self, "traffic_pct", _check_pct(self.traffic_pct))

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "traffic_pct": self.traffic_pct,
        }


@dataclass(frozen=True)
class RouteDecision:
    """Where one request was routed."""

    request_id: str
    version: str
    served_by: str  # "stable" | "canary"
    draw: float

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "request_id": self.request_id,
            "version": self.version,
            "served_by": self.served_by,
            "draw": self.draw,
        }


@dataclass(frozen=True)
class PromotionReport:
    """Record of a promotion: which version became stable."""

    previous_stable: str
    promoted: str

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "previous_stable": self.previous_stable,
            "promoted": self.promoted,
        }


@dataclass(frozen=True)
class CanaryStatus:
    """Current controller status: stable version plus any live canary."""

    stable_version: str
    canary: Canary | None

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "stable_version": self.stable_version,
            "canary": self.canary.as_dict() if self.canary is not None else None,
        }


class CanaryController:
    """Deterministic canary traffic splitter with promote/rollback."""

    def __init__(self, stable_version: str) -> None:
        self._stable_version = _check_version_text(stable_version, "stable_version")
        self._canary: Canary | None = None
        self._events: list[dict] = []

    # -- lifecycle ------------------------------------------------------

    def deploy_canary(self, version: str, traffic_pct: float) -> Canary:
        """Stage a canary release. Refused while one is already live."""
        if self._canary is not None:
            raise CanaryError(
                f"canary {self._canary.version!r} already live; "
                "promote or roll back before deploying another"
            )
        canary = Canary(version=version, traffic_pct=traffic_pct)
        if canary.version == self._stable_version:
            raise CanaryError("canary version must differ from the stable version")
        self._canary = canary
        self._events.append(
            {"event": "deployed", "version": canary.version, "traffic_pct": canary.traffic_pct}
        )
        return canary

    def promote(self) -> PromotionReport:
        """Make the live canary the stable version. Raises if none is live."""
        if self._canary is None:
            raise CanaryError("no canary deployed; nothing to promote")
        report = PromotionReport(previous_stable=self._stable_version, promoted=self._canary.version)
        self._stable_version = self._canary.version
        self._canary = None
        self._events.append({"event": "promoted", "version": report.promoted})
        return report

    def rollback(self) -> str:
        """Drop the live canary; stable is unchanged. Raises if none is live."""
        if self._canary is None:
            raise CanaryError("no canary deployed; nothing to roll back")
        dropped = self._canary.version
        self._canary = None
        self._events.append({"event": "rolled-back", "version": dropped})
        return dropped

    # -- routing ----------------------------------------------------------

    def route(self, request: Any) -> RouteDecision:
        """Route one request to stable or canary based on the traffic split."""
        request_id = _request_id_of(request)
        draw = _draw(request_id)
        if self._canary is not None and draw < self._canary.traffic_pct:
            return RouteDecision(
                request_id=request_id,
                version=self._canary.version,
                served_by="canary",
                draw=draw,
            )
        return RouteDecision(
            request_id=request_id,
            version=self._stable_version,
            served_by="stable",
            draw=draw,
        )

    # -- views ------------------------------------------------------------

    def status(self) -> CanaryStatus:
        return CanaryStatus(stable_version=self._stable_version, canary=self._canary)

    def events(self) -> tuple:
        return tuple(self._events)

    def canary_audit_event(self, decision: RouteDecision, seq: int) -> dict:
        """Shape an audit.ndjson/1-style record for one routing decision."""
        if not isinstance(decision, RouteDecision):
            raise TypeError("decision must be a RouteDecision")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise TypeError("seq must be a non-negative int")
        record = decision.as_dict()
        record["audit_seq"] = seq
        return record


def main() -> None:
    controller = CanaryController("agent-v1")
    assert controller.route("req-1").served_by == "stable"
    controller.deploy_canary("agent-v2", 100.0)
    assert controller.route("req-1").served_by == "canary"
    report = controller.promote()
    assert report.promoted == "agent-v2"
    assert controller.route("req-1").served_by == "stable"
    assert controller.status().stable_version == "agent-v2"
    print("canary-controller OK: route, promote, audit")


if __name__ == "__main__":
    main()
