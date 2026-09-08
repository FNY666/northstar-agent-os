"""Versioned, tamper-evident persistence for bounded RouteEvent records."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from route_ledger import RouteEvent, RouteLedger, RouteReceipt

_SCHEMA = "northstar.route-lineage.v2"
_DIGEST_PREFIX = "sha256:"
_IDENTITY_FIELDS = (
    "route_id", "task_id", "thread_id", "run_id", "actor_id", "workspace_id",
    "policy_revision", "step_id", "trace_id", "target_agent_id", "provider",
    "backend_version",
)


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


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


def _positive(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{field} must be positive integer")
    return value


@dataclass(frozen=True)
class LineageCursor:
    sequence: int
    event_digest: str

    def __post_init__(self) -> None:
        _positive(self.sequence, "sequence")
        _digest_field(self.event_digest, "event_digest")

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "event_digest": self.event_digest,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "LineageCursor":
        if not isinstance(value, dict) or set(value) != {"sequence", "event_digest"}:
            raise ValueError("lineage cursor is invalid")
        return cls(
            sequence=_positive(value["sequence"], "sequence"),
            event_digest=_digest_field(value["event_digest"], "event_digest"),
        )


@dataclass(frozen=True)
class LineageEvent:
    schema_version: str
    sequence: int
    prev_event_digest: str | None
    event_digest: str
    route_event: RouteEvent

    @classmethod
    def create(
        cls,
        route_event: RouteEvent,
        *,
        sequence: int,
        prev_event_digest: str | None,
    ) -> "LineageEvent":
        if not isinstance(route_event, RouteEvent):
            raise ValueError("route_event is invalid")
        sequence = _positive(sequence, "sequence")
        if sequence == 1:
            if prev_event_digest is not None:
                raise ValueError("first lineage event cannot have predecessor")
        else:
            if prev_event_digest is None:
                raise ValueError("lineage predecessor is required")
            _digest_field(prev_event_digest, "prev_event_digest")
        unsigned = {
            "schema_version": _SCHEMA,
            "sequence": sequence,
            "prev_event_digest": prev_event_digest,
            "route_event": route_event.to_dict(),
        }
        return cls(
            schema_version=_SCHEMA,
            sequence=sequence,
            prev_event_digest=prev_event_digest,
            event_digest=_digest(unsigned),
            route_event=route_event,
        )

    @classmethod
    def from_dict(cls, value: Any) -> "LineageEvent":
        fields = {
            "schema_version",
            "sequence",
            "prev_event_digest",
            "event_digest",
            "route_event",
        }
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("lineage event has unknown or missing fields")
        if value["schema_version"] != _SCHEMA:
            raise ValueError("lineage event schema is invalid")
        route_event = RouteEvent.from_dict(value["route_event"])
        for field in _IDENTITY_FIELDS:
            if value.get("route_event", {}).get(field) != getattr(route_event, field):
                raise ValueError(f"route lineage {field} does not match event")
        sequence = _positive(value["sequence"], "sequence")
        predecessor = value["prev_event_digest"]
        if sequence == 1:
            if predecessor is not None:
                raise ValueError("first lineage event cannot have predecessor")
        else:
            _digest_field(predecessor, "prev_event_digest")
        event_digest = _digest_field(value["event_digest"], "event_digest")
        result = cls(
            schema_version=_SCHEMA,
            sequence=sequence,
            prev_event_digest=predecessor,
            event_digest=event_digest,
            route_event=route_event,
        )
        expected = _digest(
            {
                "schema_version": _SCHEMA,
                "sequence": sequence,
                "prev_event_digest": predecessor,
                "route_event": route_event.to_dict(),
            }
        )
        if event_digest != expected:
            raise ValueError("lineage event digest does not match event")
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "prev_event_digest": self.prev_event_digest,
            "event_digest": self.event_digest,
            "route_event": self.route_event.to_dict(),
        }


@dataclass(frozen=True)
class LineageRecovery:
    verdict: str
    events: tuple[LineageEvent, ...]
    cursor: LineageCursor | None


class RouteLineage:
    def __init__(self, path: str | Path):
        self.path = Path(path).absolute()
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_path.touch(mode=0o600, exist_ok=True)
        os.chmod(self.lock_path, 0o600)

    @contextmanager
    def _locked(self):
        try:
            with self.lock_path.open("a+b") as lock:
                os.chmod(self.lock_path, 0o600)
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
                yield
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        except OSError as error:
            raise ValueError("route lineage lock is unavailable") from error

    def _read_locked(self) -> list[LineageEvent]:
        if not self.path.exists():
            return []
        try:
            raw = self.path.read_bytes()
        except OSError as error:
            raise ValueError("route lineage cannot be read") from error
        if not raw:
            return []
        events: list[LineageEvent] = []
        for raw_line in raw.splitlines(keepends=True):
            if not raw_line.endswith((b"\n", b"\r")):
                raise ValueError("route lineage contains incomplete event")
            try:
                value = json.loads(raw_line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ValueError("route lineage contains invalid event") from error
            events.append(LineageEvent.from_dict(value))
        self._verify_chain(events)
        self._validate_route_history(events)
        return events

    @staticmethod
    def _validate_route_events(route_events: list[RouteEvent]) -> None:
        for expected, route_event in enumerate(route_events, start=1):
            if route_event.sequence != expected:
                raise ValueError("lineage route-event sequence is not contiguous")
        if route_events:
            validator = object.__new__(RouteLedger)
            validator._replay_events(route_events)

    @classmethod
    def _validate_route_history(cls, events: list[LineageEvent]) -> None:
        cls._validate_route_events([event.route_event for event in events])

    @staticmethod
    def _verify_chain(events: list[LineageEvent]) -> None:
        previous: LineageEvent | None = None
        for expected_sequence, event in enumerate(events, start=1):
            if event.sequence != expected_sequence:
                raise ValueError("lineage sequence is not contiguous")
            expected_previous = previous.event_digest if previous else None
            if event.prev_event_digest != expected_previous:
                raise ValueError("lineage predecessor does not match")
            previous = event

    def append(self, route_event: RouteEvent) -> LineageEvent:
        if not isinstance(route_event, RouteEvent):
            raise ValueError("route_event is invalid")
        with self._locked():
            events = self._read_locked()
            for existing in events:
                if existing.route_event.idempotency_key == route_event.idempotency_key:
                    if existing.route_event.to_dict() == route_event.to_dict():
                        return existing
                    raise ValueError("route lineage idempotency conflict")
            sequence = len(events) + 1
            if route_event.sequence != sequence:
                raise ValueError("route event sequence does not match lineage sequence")
            previous = events[-1].event_digest if events else None
            event = LineageEvent.create(
                route_event,
                sequence=sequence,
                prev_event_digest=previous,
            )
            self._validate_route_history(events + [event])
            self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                with self.path.open("ab") as stream:
                    stream.write(_canonical(event.to_dict()) + b"\n")
                    stream.flush()
                    os.fsync(stream.fileno())
            except OSError as error:
                raise ValueError("route lineage could not be appended") from error
            return event
    def recover(self, *, expected_cursor: LineageCursor | None = None) -> LineageRecovery:
        with self._locked():
            events = self._read_locked()
        cursor = None if not events else LineageCursor(events[-1].sequence, events[-1].event_digest)
        if expected_cursor is not None and expected_cursor != cursor:
            raise ValueError("lineage recovery cursor does not match history")
        return LineageRecovery("verified", tuple(events), cursor)


def migrate_v1_to_v2(source_path: str | Path, target_path: str | Path) -> LineageRecovery:
    """Copy a validated v1 RouteEvent JSONL into a new v2 lineage file."""
    source = Path(source_path).absolute()
    target = Path(target_path).absolute()
    if source == target:
        raise ValueError("lineage migration source and target must differ")
    if target.exists():
        raise ValueError("lineage migration target already exists")
    try:
        raw = source.read_bytes()
    except OSError as error:
        raise ValueError("lineage migration source cannot be read") from error
    if not raw:
        raise ValueError("lineage migration source is empty")

    route_events: list[RouteEvent] = []
    for raw_line in raw.splitlines(keepends=True):
        if not raw_line.endswith((b"\n", b"\r")):
            raise ValueError("lineage migration source has incomplete event")
        try:
            route_events.append(RouteEvent.from_dict(json.loads(raw_line.decode("utf-8"))))
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
            raise ValueError("lineage migration source contains invalid event") from error
    for expected, route_event in enumerate(route_events, start=1):
        if route_event.sequence != expected:
            raise ValueError("lineage migration source sequence is not contiguous")
    RouteLineage._validate_route_events(route_events)

    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.migration-",
        dir=str(target.parent),
    )
    os.chmod(temporary_name, 0o600)
    temporary = Path(temporary_name)
    try:
        previous: str | None = None
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            for sequence, route_event in enumerate(route_events, start=1):
                event = LineageEvent.create(
                    route_event,
                    sequence=sequence,
                    prev_event_digest=previous,
                )
                stream.write(_canonical(event.to_dict()) + b"\n")
                previous = event.event_digest
            stream.flush()
            os.fsync(stream.fileno())
        recovery = RouteLineage(temporary).recover()
        if target.exists():
            raise ValueError("lineage migration target already exists")
        os.link(temporary, target)
        temporary.unlink()
        try:
            temporary.with_name(temporary.name + ".lock").unlink()
        except FileNotFoundError:
            pass
        return recovery
    except (OSError, ValueError) as error:
        if fd != -1:
            os.close(fd)
        for candidate in (temporary, temporary.with_name(temporary.name + ".lock")):
            try:
                candidate.unlink()
            except FileNotFoundError:
                pass
        if isinstance(error, ValueError):
            raise
        raise ValueError("lineage migration could not publish target") from error
