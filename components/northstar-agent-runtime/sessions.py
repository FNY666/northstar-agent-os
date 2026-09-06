"""Append-only JSONL session storage.

Every record is one JSON object per line. Each write is flushed and
``fsync``ed before it returns, so a crash never leaves a recorded event
missing from a file that claims to have it.

On load, a **truncated last line is skipped, not an error** — a crash mid-
write is expected in the field. (Corrupt non-final lines are skipped
defensively as well.)
"""
from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any


def load_records(path: str | Path) -> list[dict[str, Any]]:
    """Read a session file, skipping a truncated trailing line."""
    file_path = Path(path)
    if not file_path.exists():
        return []
    lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    records: list[dict[str, Any]] = []
    for index, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            if index == len(lines) - 1:
                continue  # truncated tail: skip, don't raise
            continue  # defensive: corrupt mid-file line
        if isinstance(value, dict):
            records.append(value)
    return records


class SessionStore:
    """Append-only event log for one session id.

    The session id is generated when the store is created (or resumed from an
    existing file), so callers always have a correlation id even when no
    store is configured at all — the loop falls back to a generated id.
    """

    def __init__(self, path: str | Path, session_id: str | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if session_id is None:
            session_id = self._existing_session_id()
        self.session_id = session_id or uuid.uuid4().hex

    def _existing_session_id(self) -> str | None:
        for record in load_records(self.path):
            value = record.get("session_id")
            if isinstance(value, str) and value:
                return value
        return None

    def append(self, record: dict[str, Any]) -> None:
        payload = {"session_id": self.session_id, **record}
        line = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())
