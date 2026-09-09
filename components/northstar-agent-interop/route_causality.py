"""Typed causal edges derived from verified Route Lineage events."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Sequence

from route_lineage import LineageEvent
from route_state import RouteStateMachine

_DIGEST_PREFIX = "sha256:"
_GRAPH_SCHEMA = "northstar.causal-graph.v1"
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


def canonical_graph_commitment(
    *,
    segment_lengths: Sequence[int],
    event_digests: Sequence[str],
    edges: Sequence["CausalEdge"],
    handoffs: Sequence["HandoffLink"],
) -> dict[str, Any]:
    return {
        "schema_version": _GRAPH_SCHEMA,
        "segment_lengths": list(segment_lengths),
        "event_digests": list(event_digests),
        "edges": [edge.to_dict() for edge in edges],
        "handoffs": [link.to_dict() for link in handoffs],
    }


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

    @classmethod
    def from_dict(cls, value: Any) -> "HandoffLink":
        fields = {
            "handoff_id", "parent_event_digest", "child_event_digest",
            "source_agent_id", "target_agent_id",
        }
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("handoff link has unknown or missing fields")
        return cls(
            handoff_id=value["handoff_id"],
            parent_event_digest=value["parent_event_digest"],
            child_event_digest=value["child_event_digest"],
            source_agent_id=value["source_agent_id"],
            target_agent_id=value["target_agent_id"],
        )


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
        if relation == "handoff" and handoff_id is None:
            raise ValueError("handoff edge requires handoff_id")
        if relation != "handoff" and handoff_id is not None:
            raise ValueError("non-handoff edge cannot have handoff_id")
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
    segment_lengths: tuple[int, ...] = ()
    handoffs: tuple[HandoffLink, ...] = ()

    @property
    def graph_digest(self) -> str:
        self.verify()
        return _digest(self._commitment())

    def _commitment(self) -> dict[str, Any]:
        return canonical_graph_commitment(
            segment_lengths=self.segment_lengths or (len(self.events),),
            event_digests=tuple(event.event_digest for event in self.events),
            edges=self.edges,
            handoffs=self.handoffs,
        )

    @staticmethod
    def _checked_events(events: Sequence[LineageEvent]) -> tuple[LineageEvent, ...]:
        checked: list[LineageEvent] = []
        for event in events:
            if not isinstance(event, LineageEvent):
                raise ValueError("lineage event is invalid")
            try:
                checked.append(LineageEvent.from_dict(event.to_dict()))
            except (TypeError, ValueError) as error:
                raise ValueError("lineage event is forged or invalid") from error
        return tuple(checked)

    @classmethod
    def _segment_edges(cls, events: tuple[LineageEvent, ...]) -> tuple[CausalEdge, ...]:
        if not events:
            raise ValueError("lineage segment is empty")
        cls._verify_lineage_chain(events)
        RouteStateMachine.replay([event.route_event for event in events])
        edges: list[CausalEdge] = []
        for parent, child in zip(events, events[1:]):
            relation = "receipt"
            if (
                parent.route_event.event_type == "route.failed"
                and child.route_event.event_type == "route.started"
                and parent.route_event.attempt + 1 == child.route_event.attempt
                and parent.route_event.payload["receipt"]["retryable"]
            ):
                relation = "retry"
            edges.append(CausalEdge.create(relation, parent.event_digest, child.event_digest))
        return tuple(edges)

    @classmethod
    def from_events(
        cls,
        events: Sequence[LineageEvent],
        *,
        handoffs: Sequence[HandoffLink] = (),
    ) -> "CausalGraph":
        if not isinstance(events, Sequence):
            raise ValueError("lineage events must be a sequence")
        checked = cls._checked_events(events)
        if not checked:
            raise ValueError("lineage segment is empty")
        graph = cls(
            events=checked,
            edges=cls._segment_edges(checked),
            segment_lengths=(len(checked),),
            handoffs=tuple(handoffs),
        )
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
        checked_segments = tuple(cls._checked_events(segment) for segment in segments)
        if any(not segment for segment in checked_segments):
            raise ValueError("lineage segment is empty")
        all_events = tuple(event for segment in checked_segments for event in segment)
        all_edges = [
            edge
            for segment in checked_segments
            for edge in cls._segment_edges(segment)
        ]
        graph = cls(
            events=all_events,
            edges=tuple(all_edges),
            segment_lengths=tuple(len(segment) for segment in checked_segments),
            handoffs=tuple(handoffs),
        )
        event_by_digest = {event.event_digest: event for event in all_events}
        segment_map = cls._segment_map(all_events, graph.segment_lengths)
        seen_handoffs: set[str] = set()
        for link in graph.handoffs:
            if link.handoff_id in seen_handoffs:
                raise ValueError("duplicate handoff id")
            seen_handoffs.add(link.handoff_id)
            all_edges.append(cls._validate_handoff(
                link,
                event_by_digest=event_by_digest,
                segment_map=segment_map,
            ))
        graph = cls(
            events=all_events,
            edges=tuple(all_edges),
            segment_lengths=graph.segment_lengths,
            handoffs=graph.handoffs,
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

    @staticmethod
    def _segment_map(
        events: tuple[LineageEvent, ...],
        lengths: tuple[int, ...],
    ) -> dict[str, tuple[int, int, int]]:
        result: dict[str, tuple[int, int, int]] = {}
        offset = 0
        for segment_index, length in enumerate(lengths):
            for position, event in enumerate(events[offset:offset + length]):
                result[event.event_digest] = (segment_index, position, length)
            offset += length
        return result

    @classmethod
    def _validate_handoff(
        cls,
        link: HandoffLink,
        *,
        event_by_digest: dict[str, LineageEvent],
        segment_map: dict[str, tuple[int, int, int]],
    ) -> CausalEdge:
        if not isinstance(link, HandoffLink):
            raise ValueError("handoff link is invalid")
        parent = event_by_digest.get(link.parent_event_digest)
        child = event_by_digest.get(link.child_event_digest)
        if parent is None or child is None:
            raise ValueError("handoff references unknown lineage event")
        parent_segment = segment_map[link.parent_event_digest]
        child_segment = segment_map[link.child_event_digest]
        if parent_segment[0] == child_segment[0]:
            raise ValueError("handoff must connect different route segments")
        if parent_segment[1] != parent_segment[2] - 1:
            raise ValueError("handoff parent must be terminal route event")
        if child_segment[1] != 0:
            raise ValueError("handoff child must be first decision event")
        if parent.route_event.event_type not in {"route.succeeded", "route.failed", "route.cancelled"}:
            raise ValueError("handoff parent must be terminal route event")
        if child.route_event.event_type != "decision.selected":
            raise ValueError("handoff child must be decision event")
        for field in _HANDOFF_SHARED_FIELDS:
            if getattr(parent.route_event, field) != getattr(child.route_event, field):
                raise ValueError(f"handoff {field} does not match")
        if parent.route_event.target_agent_id != link.source_agent_id:
            raise ValueError("handoff source does not match parent target")
        if child.route_event.target_agent_id != link.target_agent_id:
            raise ValueError("handoff target does not match child target")
        return CausalEdge.create(
            "handoff",
            link.parent_event_digest,
            link.child_event_digest,
            handoff_id=link.handoff_id,
        )

    def verify(self) -> None:
        checked_events = self._checked_events(self.events)
        if not checked_events:
            raise ValueError("causal graph has no lineage events")
        if checked_events != self.events:
            raise ValueError("causal graph contains non-canonical events")
        if len({event.event_digest for event in checked_events}) != len(checked_events):
            raise ValueError("causal graph contains duplicate event digest")

        lengths = self.segment_lengths or (len(checked_events),)
        if (
            not isinstance(lengths, tuple)
            or not lengths
            or any(not isinstance(length, int) or isinstance(length, bool) or length <= 0 for length in lengths)
            or sum(lengths) != len(checked_events)
        ):
            raise ValueError("causal graph segment boundaries are invalid")
        segments: list[tuple[LineageEvent, ...]] = []
        offset = 0
        for length in lengths:
            segment = checked_events[offset:offset + length]
            if len(segment) != length:
                raise ValueError("causal graph segment boundaries are invalid")
            segments.append(segment)
            offset += length

        expected_edges = tuple(
            edge
            for segment in segments
            for edge in self._segment_edges(segment)
        )
        event_by_digest = {event.event_digest: event for event in checked_events}
        segment_map = self._segment_map(checked_events, lengths)
        seen_handoffs: set[str] = set()
        checked_handoffs: list[HandoffLink] = []
        for link in self.handoffs:
            if not isinstance(link, HandoffLink):
                raise ValueError("handoff link is invalid")
            try:
                checked_handoffs.append(HandoffLink.from_dict(link.to_dict()))
            except (TypeError, ValueError) as error:
                raise ValueError("handoff link is forged or invalid") from error
            link = checked_handoffs[-1]
            if link.handoff_id in seen_handoffs:
                raise ValueError("duplicate handoff id")
            seen_handoffs.add(link.handoff_id)
            expected_edges += (self._validate_handoff(
                link,
                event_by_digest=event_by_digest,
                segment_map=segment_map,
            ),)

        checked_edges: list[CausalEdge] = []
        for edge in self.edges:
            if not isinstance(edge, CausalEdge):
                raise ValueError("causal edge is invalid")
            try:
                checked_edges.append(CausalEdge.from_dict(edge.to_dict()))
            except (TypeError, ValueError) as error:
                raise ValueError("causal edge is forged or invalid") from error
        if len({edge.edge_digest for edge in checked_edges}) != len(checked_edges):
            raise ValueError("causal graph contains duplicate edge digest")
        for edge in checked_edges:
            if edge.parent_event_digest not in event_by_digest or edge.child_event_digest not in event_by_digest:
                raise ValueError("causal edge references unknown event")
        if tuple(edge.to_dict() for edge in checked_edges) != tuple(edge.to_dict() for edge in expected_edges):
            raise ValueError("causal graph edges do not match verified lineage")
