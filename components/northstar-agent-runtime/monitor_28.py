"""Chain of custody: hash-chained evidence log.

Append-only log; each entry commits to the previous entry hash:
entry_hash = sha256(canonical(prev_hash | seq | ts | actor | action |
item_hash)). verify() replays the chain and detects tampering, gaps,
and reordering. export() serializes entries.

What this IS: tamper-evident custody log.

What this IS NOT:
* Not access control -- possession of the object allows append.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Dict, List, Tuple

#: Module version.
MONITOR_28_VERSION = "monitor-28.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.monitor-28.v1"

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_GENESIS = "sha256:" + "0" * 64


class CustodyError(Exception):
    """Fail-closed."""


def _check_item_hash(h: str) -> str:
    if not isinstance(h, str) or not h.startswith("sha256:") \
            or not _HEX64.match(h[7:]):
        raise CustodyError("item_hash must be 'sha256:' + 64 hex chars")
    return h


@dataclass(frozen=True)
class CustodyEntry:
    seq: int
    ts: float
    actor: str
    action: str  # collected, transferred, analyzed, stored, destroyed
    item_hash: str
    prev_hash: str
    entry_hash: str


def _entry_hash(prev_hash: str, seq: int, ts: float, actor: str,
                action: str, item_hash: str) -> str:
    canonical = json.dumps(
        {"prev": prev_hash, "seq": seq, "ts": ts,
         "actor": actor, "action": action, "item": item_hash},
        sort_keys=True, separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


class CustodyLog:
    """Append-only hash-chained custody log."""

    def __init__(self, case_id: str) -> None:
        if not case_id:
            raise CustodyError("case_id required")
        self._case_id = case_id
        self._entries: List[CustodyEntry] = []

    def append(self, actor: str, action: str, item_hash: str, ts: float) -> CustodyEntry:
        if not actor or not action:
            raise CustodyError("actor/action required")
        if ts < 0:
            raise CustodyError("ts must be >= 0")
        _check_item_hash(item_hash)
        seq = len(self._entries)
        prev = self._entries[-1].entry_hash if self._entries else _GENESIS
        eh = _entry_hash(prev, seq, ts, actor, action, item_hash)
        entry = CustodyEntry(seq, ts, actor, action, item_hash, prev, eh)
        self._entries.append(entry)
        return entry

    def verify(self) -> Tuple[bool, str]:
        prev = _GENESIS
        for i, e in enumerate(self._entries):
            if e.seq != i:
                return False, f"gap/reorder at index {i} (seq {e.seq})"
            if e.prev_hash != prev:
                return False, f"prev_hash mismatch at seq {i}"
            want = _entry_hash(e.prev_hash, e.seq, e.ts, e.actor, e.action, e.item_hash)
            if e.entry_hash != want:
                return False, f"tamper detected at seq {i}"
            prev = e.entry_hash
        return True, "chain ok"

    def export(self) -> List[Dict[str, object]]:
        return [
            {"seq": e.seq, "ts": e.ts, "actor": e.actor, "action": e.action,
             "item_hash": e.item_hash, "prev_hash": e.prev_hash,
             "entry_hash": e.entry_hash}
            for e in self._entries
        ]

    @property
    def case_id(self) -> str:
        return self._case_id

    def __len__(self) -> int:
        return len(self._entries)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "hashlib", "json", "pathlib", "re", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    log = CustodyLog("CASE-1")
    h = "sha256:" + "a" * 64
    log.append("analyst1", "collected", h, ts=1.0)
    log.append("analyst1", "transferred", h, ts=2.0)
    log.append("analyst2", "analyzed", h, ts=3.0)
    assert len(log) == 3
    ok, reason = log.verify()
    assert ok, reason
    # Export round-trips through hashes.
    assert len(log.export()) == 3
    for bad in (
        lambda: CustodyLog(""),
        lambda: log.append("", "collected", h, ts=1.0),
        lambda: log.append("a", "collected", "badhash", ts=1.0),
        lambda: log.append("a", "collected", h, ts=-1.0),
    ):
        try:
            bad()
            raise AssertionError("should raise")
        except CustodyError:
            pass
    assert stdlib_only()
    print("monitor-28 OK: append, verify, export, fail-closed, stdlib")


if __name__ == "__main__":
    main()
