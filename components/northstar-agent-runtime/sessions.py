"""Append-only JSONL session transcripts.

Every record is written with ``O_APPEND`` and fsynced before the call returns, so
a run that dies mid-turn leaves a transcript a human can read rather than a
half-written file. A crash that lands inside a single line can only ever damage
the *last* line, and a truncated final line is skipped instead of raising: losing
the tail of a session is survivable, refusing to open the file is not.

A session id is always issued, even when no store is configured, so tracing and
host logs can still be correlated to a run that writes nothing to disk.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

from providers.base import (
    AssistantMessage,
    ResultMessage,
    SystemMessage,
    Usage,
    UserMessage,
    coerce_blocks,
)

RECORD_TYPES: tuple[str, ...] = (
    "session_start",
    "user_prompt",
    "assistant",
    "tool_result",
    "hook",
    "denial",
    "compact_boundary",
    "informational",
    # The independent end-of-run verdict (postconditions.py): its own type so an
    # audit consumer can require it instead of grepping informational records.
    "postconditions",
    # The governance tree changed under this run (governance_watch.py). Its own type for the
    # same reason: a reader must be able to *require* its absence, not grep for it.
    "governance_drift",
    # A resumable turn boundary (checkpoints.py): transcript length + digest plus
    # the consumed counters, so a resume cannot restart the ceilings.
    "checkpoint",
    "subagent",
    "result",
    "session_end",
)

SESSION_FILE_SUFFIX = ".jsonl"
MAX_RECORD_CHARS = 200_000
TRUNCATION_NOTE = "[truncated by the session recorder]"


class SessionIntegrityError(ValueError):
    """Raised for corruption that is not explainable by a crash at the tail."""


def new_session_id(*, now: float | None = None) -> str:
    """Sortable, collision-resistant identifier: ``ns-<utc>-<entropy>``."""
    stamp = time.gmtime(now if now is not None else time.time())
    return "ns-{:04d}{:02d}{:02d}T{:02d}{:02d}{:02d}Z-{}".format(
        stamp.tm_year, stamp.tm_mon, stamp.tm_mday, stamp.tm_hour, stamp.tm_min, stamp.tm_sec,
        uuid.uuid4().hex[:8],
    )


def _fsync(fd: int) -> None:  # pragma: no cover - thin wrapper, patched in tests
    os.fsync(fd)


@dataclass
class SessionStore:
    """Writer/reader for one session's JSONL transcript."""

    directory: str | os.PathLike[str] | None = None
    session_id: str = ""
    fsync: Callable[[int], None] = field(default=_fsync)
    durable: bool = True
    max_record_chars: int = MAX_RECORD_CHARS
    on_write: Callable[[dict[str, Any]], None] | None = None
    _index: int = 0
    _written: int = 0

    def __post_init__(self) -> None:
        self.session_id = self.session_id or new_session_id()
        if self.directory is None:
            return
        path = Path(self.directory)
        existed = path.exists()
        path.mkdir(parents=True, exist_ok=True)
        if not existed:
            # Transcripts can contain user content; keep the directory owner-only.
            os.chmod(path, 0o700)
        self.directory = path

    # -- shape ------------------------------------------------------------
    @property
    def enabled(self) -> bool:
        return self.directory is not None

    @property
    def path(self) -> Path | None:
        if self.directory is None:
            return None
        return Path(self.directory) / f"{self.session_id}{SESSION_FILE_SUFFIX}"

    @property
    def written(self) -> int:
        return self._written

    @property
    def bytes_written(self) -> int:
        path = self.path
        return path.stat().st_size if path is not None and path.exists() else 0

    # -- writing ----------------------------------------------------------
    def append(self, record_type: str, data: dict[str, Any] | None = None) -> dict[str, Any] | None:
        """Write one record. Returns the record even when no store is configured."""
        if record_type not in RECORD_TYPES:
            raise ValueError(f"unknown session record type {record_type!r}")
        payload = dict(data or {})
        record: dict[str, Any] = {
            "index": self._index,
            "ts": _timestamp(),
            "session_id": self.session_id,
            "type": record_type,
            **payload,
        }
        self._index += 1
        if self.on_write is not None:
            try:
                self.on_write(record)
            except Exception:  # noqa: BLE001 - a mirror must never break the run
                pass
        if self.directory is None:
            return None
        self._write(record)
        return record

    def _write(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
        if self.max_record_chars > 0 and len(line) > self.max_record_chars:
            record = {**record, "truncated": True, "payload": record.get("payload", {})}
            line = json.dumps(record, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
            line = line[: self.max_record_chars] + ',"note":"' + TRUNCATION_NOTE + '"}'
            try:
                json.loads(line)
            except json.JSONDecodeError:  # pragma: no cover - keep valid JSON or drop the tail
                line = json.dumps(
                    {"index": record["index"], "ts": record["ts"], "session_id": self.session_id,
                     "type": record["type"], "truncated": True},
                    ensure_ascii=False, separators=(",", ":"),
                )
        path = self.path
        assert path is not None
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, (line + "\n").encode("utf-8"))
            if self.durable:
                self.fsync(fd)
        finally:
            os.close(fd)
        self._written += 1

    def record_assistant(self, message: AssistantMessage, *, agent: str = "main") -> dict[str, Any] | None:
        return self.append(
            "assistant",
            {
                "agent": agent,
                "role": "assistant",
                "content": [block.to_api() for block in message.content],
                "model": message.model,
                "usage": message.usage.as_dict(),
                "stop_reason": message.stop_reason,
            },
        )

    def record_user(self, message: UserMessage, *, agent: str = "main") -> dict[str, Any] | None:
        return self.append(
            "user_prompt" if not message.tool_results else "tool_result",
            {
                "agent": agent,
                "role": "user",
                "content": [block.to_api() for block in message.content],
                "is_meta": message.is_meta,
            },
        )

    def record_system(self, message: SystemMessage, *, agent: str = "main") -> dict[str, Any] | None:
        kind = {
            "init": "session_start",
            "compact_boundary": "compact_boundary",
            "postconditions": "postconditions",
            "governance_drift": "governance_drift",
        }.get(message.subtype, "informational")
        return self.append(kind, {"agent": agent, "subtype": message.subtype, "content": message.content, "data": message.data})

    def record_result(self, message: ResultMessage) -> dict[str, Any] | None:
        record = self.append(
            "result",
            {
                "subtype": message.subtype,
                "is_error": message.is_error,
                "num_turns": message.num_turns,
                "duration_ms": message.duration_ms,
                "total_cost_usd": message.total_cost_usd,
                "total_usage": message.total_usage.as_dict(),
                "pricing_estimated": message.pricing_estimated,
                "errors": list(message.errors),
                "permission_denials": list(message.permission_denials),
            },
        )
        self.append("session_end", {"subtype": message.subtype})
        return record

    # -- reading ----------------------------------------------------------
    def read(self, session_id: str | None = None, *, strict: bool = True) -> tuple[list[dict[str, Any]], int]:
        path = self.path if session_id is None else Path(self.directory) / f"{session_id}{SESSION_FILE_SUFFIX}"
        if path is None or not path.exists():
            return [], 0
        return load_jsonl(path, strict=strict)

    def transcript(self, session_id: str | None = None) -> list[Any]:
        records, _dropped = self.read(session_id)
        return transcript_from_records(records)

    def list_sessions(self) -> tuple[str, ...]:
        if self.directory is None:
            return ()
        return tuple(
            sorted(path.name[: -len(SESSION_FILE_SUFFIX)] for path in Path(self.directory).glob(f"*{SESSION_FILE_SUFFIX}"))
        )


def load_jsonl(path: str | os.PathLike[str], *, strict: bool = True) -> tuple[list[dict[str, Any]], int]:
    """Return ``(records, dropped)`` for a session file.

    A trailing line that cannot be parsed is a torn write and is skipped. A bad
    line anywhere earlier cannot be a torn write - that file was already damaged
    while it was complete - so ``strict`` raises instead of quietly losing turns.
    """
    file_path = Path(path)
    records: list[dict[str, Any]] = []
    dropped = 0
    with open(file_path, "r", encoding="utf-8", errors="replace") as handle:
        lines = handle.read().splitlines()
    last_index = len(lines) - 1
    for index, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            if index == last_index or not strict:
                dropped += 1
                continue
            raise SessionIntegrityError(
                f"{file_path.name}: record {index} is not valid JSON and is not the trailing line; "
                "an append-only transcript cannot be damaged here by a crash"
            ) from None
        if not isinstance(value, dict):
            if index == last_index or not strict:
                dropped += 1
                continue
            raise SessionIntegrityError(f"{file_path.name}: record {index} is not an object")
        records.append(value)
    return records, dropped


def transcript_from_records(records: Sequence[dict[str, Any]]) -> list[Any]:
    """Rebuild a provider-ready transcript from stored records."""
    transcript: list[Any] = []
    for record in records:
        kind = record.get("type")
        if kind in {"user_prompt", "tool_result", "assistant"}:
            role = record.get("role") or ("assistant" if kind == "assistant" else "user")
            content = coerce_blocks(record.get("content") or ())
            if role == "assistant":
                transcript.append(
                    AssistantMessage(
                        content=tuple(content),
                        model=str(record.get("model", "") or ""),
                        usage=Usage.from_mapping(record.get("usage")),
                        stop_reason=str(record.get("stop_reason", "") or ""),
                    )
                )
            else:
                transcript.append(UserMessage(content=tuple(content), is_meta=bool(record.get("is_meta"))))
        elif kind == "compact_boundary":
            transcript.append(
                SystemMessage(
                    subtype="compact_boundary",
                    content=str(record.get("content", "") or ""),
                    data=dict(record.get("data") or {}),
                )
            )
    return transcript


def summarise(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Cheap session statistics for the CLI's ``--inspect-session`` flag."""
    counts: dict[str, int] = {}
    cost = 0.0
    turns = 0
    subtype = ""
    for record in records:
        kind = str(record.get("type", "unknown"))
        counts[kind] = counts.get(kind, 0) + 1
        if kind == "assistant":
            turns += 1
        if kind == "result":
            cost = float(record.get("total_cost_usd") or 0.0)
            subtype = str(record.get("subtype", ""))
    return {"records": sum(counts.values()), "by_type": counts, "assistant_turns": turns, "total_cost_usd": cost, "subtype": subtype}


def _timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + f".{int((time.time() % 1) * 1000):03d}Z"


def resolve_session_id(session_id: str | None, store: SessionStore | None) -> str:
    """Pitfall guard: a run without a session store still needs a session id."""
    if session_id:
        return session_id
    if store is not None and store.session_id:
        return store.session_id
    return new_session_id()


__all__ = [
    "RECORD_TYPES",
    "SESSION_FILE_SUFFIX",
    "SessionIntegrityError",
    "SessionStore",
    "load_jsonl",
    "new_session_id",
    "resolve_session_id",
    "summarise",
    "transcript_from_records",
]
