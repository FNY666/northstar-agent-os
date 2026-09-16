"""Atomic persistence for admitted, verified causal graph commitments."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import tempfile
from collections.abc import Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from interop_contract import RECOVERY_EMPTY, RECOVERY_VERIFIED
from route_causality import (
    CausalEdge,
    CausalGraph,
    HandoffLink,
    canonical_graph_commitment,
)
from route_lineage import LineageEvent

_SCHEMA = "northstar.graph-evidence.v2"
_GRAPH_SCHEMA = "northstar.causal-graph.v1"
_PREFIX = "sha256:"

PROJECTION_CURRENT = "projection-current"
PROJECTION_EXTENDED = "projection-extended"
PROJECTION_STALE = "projection-stale"
PROJECTION_UNKNOWN = "projection-unknown"


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value: Any) -> str:
    return _PREFIX + hashlib.sha256(_canonical(value)).hexdigest()


def _digest_field(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith(_PREFIX) or any(c not in "0123456789abcdef" for c in value[7:]):
        raise ValueError(f"{field} is invalid")
    return value


def _positive(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{field} must be positive integer")
    return value


def _record_unsigned(
    *,
    sequence: int,
    prev_record_digest: str | None,
    graph_digest: str,
    segment_lengths: tuple[int, ...],
    event_digests: tuple[str, ...],
    edges: tuple[CausalEdge, ...],
    handoffs: tuple[HandoffLink, ...],
) -> dict[str, Any]:
    return {
        "schema_version": _SCHEMA,
        "sequence": sequence,
        "prev_record_digest": prev_record_digest,
        "graph_digest": graph_digest,
        "segment_lengths": list(segment_lengths),
        "event_digests": list(event_digests),
        "edges": [edge.to_dict() for edge in edges],
        "handoffs": [link.to_dict() for link in handoffs],
    }


@dataclass(frozen=True)
class GraphEvidenceCursor:
    sequence: int
    record_digest: str

    def __post_init__(self) -> None:
        _positive(self.sequence, "sequence")
        _digest_field(self.record_digest, "record_digest")


@dataclass(frozen=True)
class GraphEvidenceRecord:
    schema_version: str
    sequence: int
    prev_record_digest: str | None
    record_digest: str
    graph_digest: str
    segment_lengths: tuple[int, ...]
    event_digests: tuple[str, ...]
    edges: tuple[CausalEdge, ...]
    handoffs: tuple[HandoffLink, ...]

    @classmethod
    def create(
        cls,
        graph: CausalGraph,
        *,
        sequence: int,
        prev_record_digest: str | None,
    ) -> "GraphEvidenceRecord":
        if not isinstance(graph, CausalGraph):
            raise ValueError("graph is invalid")
        graph.verify()
        sequence = _positive(sequence, "sequence")
        if sequence == 1:
            if prev_record_digest is not None:
                raise ValueError("first graph evidence record cannot have predecessor")
        else:
            _digest_field(prev_record_digest, "prev_record_digest")
        graph_digest = graph.graph_digest
        event_digests = tuple(event.event_digest for event in graph.events)
        segment_lengths = tuple(graph.segment_lengths or (len(event_digests),))
        edges = tuple(CausalEdge.from_dict(edge.to_dict()) for edge in graph.edges)
        handoffs = tuple(HandoffLink.from_dict(link.to_dict()) for link in graph.handoffs)
        unsigned = _record_unsigned(
            sequence=sequence,
            prev_record_digest=prev_record_digest,
            graph_digest=graph_digest,
            segment_lengths=segment_lengths,
            event_digests=event_digests,
            edges=edges,
            handoffs=handoffs,
        )
        return cls(
            _SCHEMA,
            sequence,
            prev_record_digest,
            _digest(unsigned),
            graph_digest,
            segment_lengths,
            event_digests,
            edges,
            handoffs,
        )

    @classmethod
    def from_dict(cls, value: Any) -> "GraphEvidenceRecord":
        fields = {
            "schema_version", "sequence", "prev_record_digest", "record_digest",
            "graph_digest", "segment_lengths", "event_digests", "edges", "handoffs",
        }
        if not isinstance(value, dict) or set(value) != fields or value["schema_version"] != _SCHEMA:
            raise ValueError("graph evidence record is invalid")
        sequence = _positive(value["sequence"], "sequence")
        previous = value["prev_record_digest"]
        if sequence == 1:
            if previous is not None:
                raise ValueError("first graph evidence record cannot have predecessor")
        else:
            _digest_field(previous, "prev_record_digest")
        segment_lengths_value = value["segment_lengths"]
        if not isinstance(segment_lengths_value, list) or not segment_lengths_value:
            raise ValueError("graph segment_lengths are invalid")
        segment_lengths = tuple(_positive(item, "segment_length") for item in segment_lengths_value)
        if sum(segment_lengths) <= 0:
            raise ValueError("graph segment_lengths are invalid")
        event_digests_value = value["event_digests"]
        if not isinstance(event_digests_value, list) or not event_digests_value:
            raise ValueError("graph event_digests are invalid")
        event_digests = tuple(_digest_field(item, "event_digest") for item in event_digests_value)
        if sum(segment_lengths) != len(event_digests):
            raise ValueError("graph segment_lengths do not cover event digests")
        if len(set(event_digests)) != len(event_digests):
            raise ValueError("graph event_digests contain duplicates")
        edges_value = value["edges"]
        if not isinstance(edges_value, list):
            raise ValueError("graph edges are invalid")
        edges = tuple(CausalEdge.from_dict(item) for item in edges_value)
        if len({edge.edge_digest for edge in edges}) != len(edges):
            raise ValueError("graph edges contain duplicates")
        edge_endpoints = {
            endpoint
            for edge in edges
            for endpoint in (edge.parent_event_digest, edge.child_event_digest)
        }
        if not edge_endpoints.issubset(set(event_digests)):
            raise ValueError("graph edge references unknown event")
        handoffs_value = value["handoffs"]
        if not isinstance(handoffs_value, list):
            raise ValueError("graph handoffs are invalid")
        handoffs = tuple(HandoffLink.from_dict(item) for item in handoffs_value)
        if len({link.handoff_id for link in handoffs}) != len(handoffs):
            raise ValueError("graph handoffs contain duplicates")
        for link in handoffs:
            if link.parent_event_digest not in event_digests or link.child_event_digest not in event_digests:
                raise ValueError("graph handoff references unknown event")
        expected_handoff_edges = {
            _canonical(CausalEdge.create(
                "handoff",
                link.parent_event_digest,
                link.child_event_digest,
                handoff_id=link.handoff_id,
            ).to_dict())
            for link in handoffs
        }
        actual_handoff_edges = {
            _canonical(edge.to_dict())
            for edge in edges
            if edge.relation == "handoff"
        }
        if actual_handoff_edges != expected_handoff_edges:
            raise ValueError("graph handoff declarations do not match edges")
        computed_graph_digest = _digest(canonical_graph_commitment(
            segment_lengths=segment_lengths,
            event_digests=event_digests,
            edges=edges,
            handoffs=handoffs,
        ))
        graph_digest = _digest_field(value["graph_digest"], "graph_digest")
        if graph_digest != computed_graph_digest:
            raise ValueError("graph digest does not match graph commitment")
        unsigned = _record_unsigned(
            sequence=sequence,
            prev_record_digest=previous,
            graph_digest=graph_digest,
            segment_lengths=segment_lengths,
            event_digests=event_digests,
            edges=edges,
            handoffs=handoffs,
        )
        record_digest = _digest_field(value["record_digest"], "record_digest")
        if record_digest != _digest(unsigned):
            raise ValueError("graph evidence record digest does not match")
        return cls(
            _SCHEMA,
            sequence,
            previous,
            record_digest,
            graph_digest,
            segment_lengths,
            event_digests,
            edges,
            handoffs,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "prev_record_digest": self.prev_record_digest,
            "record_digest": self.record_digest,
            "graph_digest": self.graph_digest,
            "segment_lengths": list(self.segment_lengths),
            "event_digests": list(self.event_digests),
            "edges": [edge.to_dict() for edge in self.edges],
            "handoffs": [link.to_dict() for link in self.handoffs],
        }


@dataclass(frozen=True)
class GraphEvidenceRecovery:
    verdict: str
    records: tuple[GraphEvidenceRecord, ...]
    cursor: GraphEvidenceCursor | None


class GraphEvidenceStore:
    def __init__(self, path: str | Path):
        self.path = Path(path).absolute()
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_path.touch(mode=0o600, exist_ok=True)
        os.chmod(self.lock_path, 0o600)

    @contextmanager
    def _locked(self):
        try:
            lock = self.lock_path.open("a+b")
        except OSError as error:
            raise ValueError("graph evidence lock is unavailable") from error
        try:
            os.chmod(self.lock_path, 0o600)
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            except OSError as error:
                raise ValueError("graph evidence lock is unavailable") from error
            yield
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            except OSError as error:
                raise ValueError("graph evidence lock release failed") from error
        finally:
            lock.close()

    def _read_locked(self) -> list[GraphEvidenceRecord]:
        if not self.path.exists():
            return []
        try:
            raw = self.path.read_bytes()
        except OSError as error:
            raise ValueError("graph evidence cannot be read") from error
        records: list[GraphEvidenceRecord] = []
        for raw_line in raw.splitlines(keepends=True):
            if not raw_line.endswith((b"\n", b"\r")):
                raise ValueError("graph evidence contains incomplete record")
            try:
                records.append(GraphEvidenceRecord.from_dict(json.loads(raw_line.decode("utf-8"))))
            except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
                raise ValueError("graph evidence contains invalid record") from error
        previous: GraphEvidenceRecord | None = None
        seen_graphs: set[str] = set()
        for expected, record in enumerate(records, start=1):
            if record.graph_digest in seen_graphs:
                raise ValueError("graph evidence contains duplicate graph")
            seen_graphs.add(record.graph_digest)
            if record.sequence != expected or record.prev_record_digest != (previous.record_digest if previous else None):
                raise ValueError("graph evidence chain is invalid")
            previous = record
        return records

    def _publish(self, records: list[GraphEvidenceRecord]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=str(self.path.parent))
        temporary = Path(name)
        try:
            os.chmod(temporary, 0o600)
            with os.fdopen(fd, "wb") as stream:
                fd = -1
                for record in records:
                    stream.write(_canonical(record.to_dict()) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        except OSError as error:
            if fd != -1:
                os.close(fd)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            raise ValueError("graph evidence publication failed") from error

    def admit(self, graph: CausalGraph) -> GraphEvidenceRecord:
        if not isinstance(graph, CausalGraph):
            raise ValueError("graph is invalid")
        graph.verify()
        with self._locked():
            records = self._read_locked()
            candidate_digest = graph.graph_digest
            for existing in records:
                if existing.graph_digest == candidate_digest:
                    return existing
            record = GraphEvidenceRecord.create(
                graph,
                sequence=len(records) + 1,
                prev_record_digest=records[-1].record_digest if records else None,
            )
            self._publish(records + [record])
            return record

    def recover(self, *, expected_cursor: GraphEvidenceCursor | None = None) -> GraphEvidenceRecovery:
        with self._locked():
            records = self._read_locked()
        cursor = None if not records else GraphEvidenceCursor(records[-1].sequence, records[-1].record_digest)
        if expected_cursor is not None and expected_cursor != cursor:
            raise ValueError("graph evidence cursor does not match history")
        # Same rule as the route lineage: a store that read no records cannot be
        # reported as verified, because a deleted or truncated file reads the same
        # way as one that was never written.
        verdict = RECOVERY_VERIFIED if records else RECOVERY_EMPTY
        return GraphEvidenceRecovery(verdict, tuple(records), cursor)


@dataclass(frozen=True)
class ProjectionVerdict:
    """Whether a stored graph projection still agrees with the source it came from."""

    verdict: str
    reason: str
    record_sequence: int | None = None
    execution_authorized: bool = False


def verify_projection_against_source(
    record: GraphEvidenceRecord,
    source_events: Sequence[LineageEvent],
    *,
    expected_record_digest: str | None = None,
) -> ProjectionVerdict:
    """Re-check a stored graph projection against the source lineage as it reads now.

    A graph projection is not a replacement for the source lineage, and until now
    nothing related the two after admission: the record stored the source event
    digests but no API read them back. That left a projection unable to answer
    whether the history it was taken from was later rolled back, truncated or
    replaced - the caller had to remember its own cursor for that.

    The recorded digests make the projection itself an anchor the caller does not
    have to remember. This never authorizes execution and never repairs anything;
    it only reports how the projection and the source currently relate.
    """
    if not isinstance(record, GraphEvidenceRecord):
        raise ValueError("graph projection record is invalid")
    if not isinstance(source_events, Sequence) or isinstance(source_events, (str, bytes)):
        raise ValueError("source lineage events are invalid")
    for event in source_events:
        if not isinstance(event, LineageEvent):
            raise ValueError("source lineage events are invalid")
    if expected_record_digest is not None:
        _digest_field(expected_record_digest, "expected_record_digest")
        if expected_record_digest != record.record_digest:
            return ProjectionVerdict(
                PROJECTION_UNKNOWN,
                "graph projection record does not match the caller pin",
                record.sequence,
            )
    if not source_events:
        return ProjectionVerdict(
            PROJECTION_UNKNOWN,
            "source lineage has no events to compare",
            None,
        )
    source_digests = tuple(event.event_digest for event in source_events)
    recorded = record.event_digests
    if source_digests[: len(recorded)] != recorded:
        return ProjectionVerdict(
            PROJECTION_STALE,
            "source lineage no longer contains the recorded events",
            record.sequence,
        )
    if len(source_digests) > len(recorded):
        return ProjectionVerdict(
            PROJECTION_EXTENDED,
            "source lineage grew past the recorded projection",
            record.sequence,
        )
    return ProjectionVerdict(
        PROJECTION_CURRENT,
        "source lineage still matches the recorded projection",
        record.sequence,
    )
