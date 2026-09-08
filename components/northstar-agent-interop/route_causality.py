"""Typed causal edges derived from verified Route Lineage events."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Sequence

from route_lineage import LineageEvent
from route_state import RouteStateMachine

_DIGEST_PREFIX = "sha256:"
_RELATIONS = {"receipt", "retry", "handoff"}
_IDENTITY_FIELDS = (
    "route_id", "task_id", "thread_id", "run_id", "actor_id", "workspace_id",
    "policy_revision", "step_id", "trace_id",
)
_HANDOFF_SHARED_FIELDS = (
    "task_id", "thread_id", "run_id", "actor_id", "workspace_id",
    "policy_revision", "trace_id",
)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value: Any) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(_canonical(value)).hexdigest()


def _digest_field(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith(_DIGEST_PREFIX)
        or any(char not in "0123456789abcdef" for char in value[7:])
    ):
        raise ValueError(f"{field} is invalid")
    return value


def _id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or any(char.isspace() or char in "/\\\x00" for char in value):
        raise ValueError(f"{field} is invalid")
    return value


@dataclass(frozen=True)
class HandoffLink:
    handoff_id: str
    parent_event_digest: str
    child_event_digest: str
    source_agent_id: str
    target_agent_id: str

    def __post_init__(self) -> None:
        _id(self.handoff_id, "handoff_id")
        _digest_field(self.parent_event_digest, "parent_event_digest")
        _digest_field(self.child_event_digest, "child_event_digest")
        _id(self.source_agent_id, "source_agent_id")
        _id(self.target_agent_id, "target_agent_id")
        if self.parent_event_digest == self.child_event_digest:
            raise ValueError("handoff cannot link an event to itself")
        if self.source_agent_id == self.target_agent_id:
            raise ValueError("handoff source and target must differ")

    def to_dict(self) -> dict[str, str]:
        return {
            "handoff_id": self.handoff_id,
            "parent_event_digest": self.parent_event_digest,
            "child_event_digest": self.child_event_digest,
            "source_agent_id": self.source_agent_id,
            "target_agent_id": self.target_agent_id,
        }


@dataclass(frozen=True)
class CausalEdge:
    relation: str
    parent_event_digest: str
    child_event_digest: str
    edge_digest: str
    handoff_id: str | None = None

    @classmethod
    def create(
        cls,
        relation: str,
        parent_event_digest: str,
        child_event_digest: str,
        *,
        handoff_id: str | None = None,
    ) -> "CausalEdge":
        if relation not in _RELATIONS:
            raise ValueError("causal relation is invalid")
        _digest_field(parent_event_digest, "parent_event_digest")
        _digest_field(child_event_digest, "child_event_digest")
        if parent_event_digest == child_event_digest:
            raise ValueError("causal edge cannot self-link")
        if handoff_id is not None:
            _id(handoff_id, "handoff_id")
        unsigned = {
            "relation": relation,
            "parent_event_digest": parent_event_digest,
            "child_event_digest": child_event_digest,
            "handoff_id": handoff_id,
        }
        return cls(
            relation=relation,
            parent_event_digest=parent_event_digest,
            child_event_digest=child_event_digest,
            edge_digest=_digest(unsigned),
            handoff_id=handoff_id,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "relation": self.relation,
            "parent_event_digest": self.parent_event_digest,
            "child_event_digest": self.child_event_digest,
            "edge_digest": self.edge_digest,
            "handoff_id": self.handoff_id,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "CausalEdge":
        fields = {"relation", "parent_event_digest", "child_event_digest", "edge_digest", "handoff_id"}
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("causal edge has unknown or missing fields")
        result = cls.create(
            value["relation"],
            value["parent_event_digest"],
            value["child_event_digest"],
            handoff_id=value["handoff_id"],
        )
        if result.edge_digest != value["edge_digest"]:
            raise ValueError("causal edge digest does not match edge")
        return result


@dataclass(frozen=True)
class CausalGraph:
    events: tuple[LineageEvent, ...]
    edges: tuple[CausalEdge, ...]

    @classmethod
    def from_events(
        cls,
        events: Sequence[LineageEvent],
        *,
        handoffs: Sequence[HandoffLink] = (),
    ) -> "CausalGraph":
        if not isinstance(events, Sequence):
            raise ValueError("lineage events must be a sequence")
        checked = tuple(events)
        for event in checked:
            if not isinstance(event, LineageEvent):
                raise ValueError("lineage event is invalid")
            LineageEvent.from_dict(event.to_dict())
        if checked:
            cls._verify_lineage_chain(checked)
            RouteStateMachine.replay([event.route_event for event in checked])
        event_by_digest = {event.event_digest: event for event in checked}
        if len(event_by_digest) != len(checked):
            raise ValueError("lineage contains duplicate event digest")

        edges: list[CausalEdge] = []
        for parent, child in zip(checked, checked[1:]):
            relation = "receipt"
            if (
                parent.route_event.event_type == "route.failed"
                and child.route_event.event_type == "route.started"
                and parent.route_event.attempt + 1 == child.route_event.attempt
            ):
                parent_receipt = parent.route_event.payload["receipt"]
                if parent_receipt["retryable"]:
                    relation = "retry"
            edges.append(CausalEdge.create(relation, parent.event_digest, child.event_digest))

        seen_handoffs: set[str] = set()
        seen_edges = {(edge.parent_event_digest, edge.child_event_digest, edge.relation) for edge in edges}
        for link in handoffs:
            if not isinstance(link, HandoffLink):
                raise ValueError("handoff link is invalid")
            if link.handoff_id in seen_handoffs:
                raise ValueError("duplicate handoff id")
            seen_handoffs.add(link.handoff_id)
            parent = event_by_digest.get(link.parent_event_digest)
            child = event_by_digest.get(link.child_event_digest)
            if parent is None or child is None:
                raise ValueError("handoff references unknown lineage event")
            parent_route = parent.route_event
            child_route = child.route_event
            for field in _IDENTITY_FIELDS:
                if getattr(parent_route, field) != getattr(child_route, field):
                    raise ValueError(f"handoff {field} does not match")
            if parent_route.target_agent_id != link.source_agent_id:
                raise ValueError("handoff source does not match parent target")
            if child_route.target_agent_id != link.target_agent_id:
                raise ValueError("handoff target does not match child target")
            edge_key = (link.parent_event_digest, link.child_event_digest, "handoff")
            if edge_key in seen_edges:
                raise ValueError("duplicate causal edge")
            seen_edges.add(edge_key)
            edges.append(CausalEdge.create(
                "handoff",
                link.parent_event_digest,
                link.child_event_digest,
                handoff_id=link.handoff_id,
            ))
        graph = cls(events=checked, edges=tuple(edges))
        graph.verify()
        return graph

    @classmethod
    def from_segments(
        cls,
        segments: Sequence[Sequence[LineageEvent]],
        *,
        handoffs: Sequence[HandoffLink] = (),
    ) -> "CausalGraph":
        if not isinstance(segments, Sequence) or not segments:
            raise ValueError("lineage segments are invalid")
        checked_segments = tuple(tuple(segment) for segment in segments)
        if any(not segment for segment in checked_segments):
            raise ValueError("lineage segment is empty")
        all_events: list[LineageEvent] = []
        edges: list[CausalEdge] = []
        for segment in checked_segments:
            segment_graph = cls.from_events(segment)
            all_events.extend(segment_graph.events)
            edges.extend(segment_graph.edges)
        if len({event.event_digest for event in all_events}) != len(all_events):
            raise ValueError("lineage segments contain duplicate event digest")
        graph = cls(events=tuple(all_events), edges=tuple(edges))
        event_by_digest = {event.event_digest: event for event in graph.events}
        seen_handoffs: set[str] = set()
        seen_edges = {(edge.parent_event_digest, edge.child_event_digest, edge.relation) for edge in graph.edges}
        for link in handoffs:
            if not isinstance(link, HandoffLink):
                raise ValueError("handoff link is invalid")
            if link.handoff_id in seen_handoffs:
                raise ValueError("duplicate handoff id")
            seen_handoffs.add(link.handoff_id)
            parent = event_by_digest.get(link.parent_event_digest)
            child = event_by_digest.get(link.child_event_digest)
            if parent is None or child is None:
                raise ValueError("handoff references unknown lineage event")
            parent_route = parent.route_event
            child_route = child.route_event
            if parent_route.event_type not in {"route.succeeded", "route.failed", "route.cancelled"}:
                raise ValueError("handoff parent must be terminal route event")
            if child_route.event_type != "decision.selected":
                raise ValueError("handoff child must be decision event")
            for field in _HANDOFF_SHARED_FIELDS:
                if getattr(parent_route, field) != getattr(child_route, field):
                    raise ValueError(f"handoff {field} does not match")
            if parent_route.target_agent_id != link.source_agent_id:
                raise ValueError("handoff source does not match parent target")
            if child_route.target_agent_id != link.target_agent_id:
                raise ValueError("handoff target does not match child target")
            edge_key = (link.parent_event_digest, link.child_event_digest, "handoff")
            if edge_key in seen_edges:
                raise ValueError("duplicate causal edge")
            seen_edges.add(edge_key)
            graph = cls(
                events=graph.events,
                edges=graph.edges + (CausalEdge.create(
                    "handoff",
                    link.parent_event_digest,
                    link.child_event_digest,
                    handoff_id=link.handoff_id,
                ),),
            )
        graph.verify()
        return graph

    @classmethod
    def _verify_lineage_chain(cls, events: tuple[LineageEvent, ...]) -> None:
        previous: LineageEvent | None = None
        for expected, event in enumerate(events, start=1):
            if event.sequence != expected:
                raise ValueError("causal lineage sequence is not contiguous")
            if event.prev_event_digest != (previous.event_digest if previous else None):
                raise ValueError("causal lineage predecessor does not match")
            previous = event

    def verify(self) -> None:
        event_digests = {event.event_digest for event in self.events}
        seen: set[tuple[str, str, str]] = set()
        for edge in self.edges:
            checked = CausalEdge.from_dict(edge.to_dict())
            key = (checked.parent_event_digest, checked.child_event_digest, checked.relation)
            if key in seen:
                raise ValueError("duplicate causal edge")
            seen.add(key)
            if checked.parent_event_digest not in event_digests or checked.child_event_digest not in event_digests:
                raise ValueError("causal edge references unknown event")
