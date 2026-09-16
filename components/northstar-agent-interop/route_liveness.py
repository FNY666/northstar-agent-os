"""Derive whether a route may accept a new attempt, from its lineage alone."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any

from route_lineage import LineageGraph, active_attempts

SCHEMA = "northstar.route-liveness.v1"
STATES = ("dispatchable", "retryable", "in_flight", "blocked", "unknown")


@dataclass(frozen=True)
class RouteLivenessVerdict:
    schema_version: str
    route_id: str
    state: str
    active_status: str
    attempt_count: int
    unverified: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
    execution_authorized: bool = False

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "route_id": self.route_id,
            "state": self.state,
            "active_status": self.active_status,
            "attempt_count": self.attempt_count,
            "unverified": list(self.unverified),
            "reasons": list(self.reasons),
            "execution_authorized": self.execution_authorized,
        }


def evaluate_route_liveness(
    graph: LineageGraph, route_id: str, *, declared_routes: Any = None
) -> RouteLivenessVerdict:
    """Report whether a route may accept a new attempt, without authorising one.

    A route with no lineage is dispatchable but its identity is not corroborated
    by anything, so it is reported as ``route_identity_unverified``: a typo or a
    route belonging to another graph looks exactly like a legitimate new route.
    A host-owned ``declared_routes`` collection corroborates the identity; a
    route outside that set is refused instead of silently reported dispatchable.
    """
    if not isinstance(graph, LineageGraph):
        raise ValueError("graph invalid")
    if not isinstance(route_id, str) or not route_id:
        raise ValueError("route_id invalid")
    unverified = ("lineage_mark_absent",) if graph.mark_state == "mark_absent" else ()

    def verdict(state, active_status, attempt_count, reasons):
        return RouteLivenessVerdict(
            SCHEMA, route_id, state, active_status, attempt_count,
            unverified, reasons, False,
        )

    attempts = active_attempts(graph, route_id)
    events = [item for item in graph.read() if item.route_id == route_id]
    if not events:
        identity_unverified = True
        if declared_routes is not None:
            try:
                declared = frozenset(declared_routes)
            except TypeError as exc:
                raise ValueError("declared_routes invalid") from exc
            if route_id not in declared:
                raise ValueError("route is not in the declared route set")
            identity_unverified = False
        if identity_unverified:
            unverified = unverified + ("route_identity_unverified",)
        return verdict("dispatchable", "", 0, ("no_prior_attempts",))
    if len(attempts) > 1:
        return verdict("unknown", "", len(attempts), ("multiple_active_attempts",))
    latest = events[-1]
    status = latest.status
    if status in ("planned", "dispatched"):
        return verdict("in_flight", status, 1, ("attempt_in_flight",))
    if status == "failed":
        if latest.retryable:
            return verdict("retryable", status, 1, ("retry_available",))
        return verdict("blocked", status, 1, ("route_terminal_failed",))
    if status == "succeeded":
        return verdict("blocked", status, 1, ("route_terminal_succeeded",))
    if status == "superseded":
        return verdict("blocked", status, 1, ("route_superseded",))
    return verdict("unknown", status, 1, ("route_state_unrecognised",))


__all__ = ["SCHEMA", "STATES", "RouteLivenessVerdict", "evaluate_route_liveness"]
