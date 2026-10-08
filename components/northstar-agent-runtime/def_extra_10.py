"""Log integrity via hash chain, Simulated.

Append-only log: each record's digest covers (index, timestamp,
previous digest, payload).  verify() re-walks the chain and reports
the first broken index.

What this IS: tamper-evident append-only log primitive.

What this IS NOT:
* Not a distributed ledger -- single-writer, host-held.
* Any break FAILS CLOSED at the first bad index.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

#: Module version.
DEF_EXTRA_10_VERSION = "def-extra-10.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.def-extra-10.v1"


class LogChainError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class LogRecord:
    """One chained log record."""

    index: int
    ts: float
    prev: str
    payload: Dict[str, Any]
    digest: str


def _digest(index: int, ts: float, prev: str, payload: Dict[str, Any]) -> str:
    body = json.dumps(
        {"index": index, "ts": ts, "prev": prev, "payload": payload},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return "sha256:" + hashlib.sha256(body).hexdigest()


class LogChain:
    """Append-only hash-chained log."""

    def __init__(self) -> None:
        self._records: List[LogRecord] = []

    def append(
        self, payload: Dict[str, Any], *, now: Optional[float] = None
    ) -> LogRecord:
        """Append a record."""
        ts = time.time() if now is None else now
        index = len(self._records)
        prev = self._records[-1].digest if self._records else "genesis"
        record = LogRecord(
            index, ts, prev, dict(payload), _digest(index, ts, prev, payload)
        )
        self._records.append(record)
        return record

    def verify(self) -> Tuple[bool, str]:
        """Re-walk the chain.  Returns (ok, detail)."""
        prev = "genesis"
        for record in self._records:
            if record.index != self._records.index(record):
                return False, f"index mismatch at {record.index}"
            if record.prev != prev:
                return False, f"prev link broken at index {record.index}"
            expected = _digest(record.index, record.ts, record.prev, record.payload)
            if not hmac.compare_digest(expected, record.digest):
                return False, f"digest mismatch at index {record.index}"
            prev = record.digest
        return True, f"chain ok ({len(self._records)} records)"

    @property
    def records(self) -> List[LogRecord]:
        return list(self._records)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__", "ast", "dataclasses", "hashlib", "hmac", "json",
        "pathlib", "time", "typing",
    }
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
    chain = LogChain()
    chain.append({"event": "start"}, now=1000.0)
    chain.append({"event": "allow", "tool": "read"}, now=1001.0)
    ok, detail = chain.verify()
    assert ok is True, detail
    # Tamper with a payload (simulate by rebuilding list with a bad record).
    records = chain.records
    tampered = LogRecord(
        records[1].index, records[1].ts, records[1].prev,
        {"event": "forged"}, records[1].digest,
    )
    chain2 = LogChain()
    chain2._records = [records[0], tampered]
    ok, detail = chain2.verify()
    assert ok is False and "digest mismatch" in detail
    assert stdlib_only()
    print("def-extra-10 OK: chain, tamper detection")


if __name__ == "__main__":
    main()
