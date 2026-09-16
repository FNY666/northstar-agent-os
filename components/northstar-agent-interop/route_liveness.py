"""Derive whether a route may accept a new attempt, from its lineage alone."""
from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from route_lineage import LineageError, LineageGraph, active_attempts, causal_chain

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

    @property
    def computed_digest(self) -> str:
        payload = json.dumps(
            self.to_dict(), ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        ).encode()
        return "sha256:" + hashlib.sha256(b"northstar.route-liveness.v1\0" + payload).hexdigest()

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


_EXECUTION_STATUSES = ("planned", "dispatched", "succeeded", "failed")


def _unresolved_branches(graph, events):
    """Open branches that no concluded attempt under the same root accounts for.

    A retry is not flagged: a concluded terminal that has any execution child is
    not counted as concluded at all, so a retry branch never reaches this check.
    Roots without any concluded attempt are left to the ordinary state logic.
    """
    children = {}
    for item in events:
        children.setdefault(item.parent_event_id, []).append(item)

    def execution_children(item):
        return [child for child in children.get(item.event_id, ()) if child.status in _EXECUTION_STATUSES]

    def chain_of(item):
        try:
            return causal_chain(graph, item.event_id)
        except LineageError:
            return ()

    chains = {item.event_id: chain_of(item) for item in events}
    root_of = {event_id: (chain[0].event_id if chain else None) for event_id, chain in chains.items()}
    concluded = {
        item.event_id: root_of[item.event_id] for item in events
        if item.status in ("succeeded", "failed") and not execution_children(item)
    }
    roots_with_conclusion = set(concluded.values())
    unresolved = []
    for item in events:
        if item.status not in ("planned", "dispatched") or execution_children(item):
            continue
        if root_of[item.event_id] not in roots_with_conclusion:
            continue
        unresolved.append(item)
    return tuple(unresolved)


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
    unresolved = _unresolved_branches(graph, events)
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
    if unresolved:
        return verdict("unknown", "", len(attempts), ("unresolved_attempt_branch",))
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
