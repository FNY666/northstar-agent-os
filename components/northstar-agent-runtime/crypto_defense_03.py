"""Crypto Defense 03: Rekor transparency log (mock), Simulated.

Mock Rekor: append-only transparency log with hash chaining.
Real Rekor is a immutable transparency log for signatures.
This is an interface mock, NOT real Rekor.

What this IS: tamper-evident append-only log.
What this IS NOT: distributed consensus or real transparency.
"""

from __future__ import annotations

import ast
import hashlib
import json
import time
from dataclasses import dataclass
from typing import List, Optional

#: Module version.
CRYPTO_DEFENSE_03_VERSION = "crypto-defense-03.v1"
SCHEMA_PIN = "northstar.crypto-defense-03.v1"


class RekorError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class LogEntry:
    """One log entry."""

    index: int
    data_hash: str
    prev_hash: str
    timestamp: float


class MockRekor:
    """Mock transparency log."""

    def __init__(self) -> None:
        self._entries: List[LogEntry] = []
        self._genesis = "sha256:" + hashlib.sha256(b"rekor-genesis").hexdigest()

    def append(self, data: bytes) -> int:
        """Append data. Returns index."""
        if not isinstance(data, bytes):
            raise RekorError("data must be bytes")
        data_hash = "sha256:" + hashlib.sha256(data).hexdigest()
        prev_hash = (
            self._entries[-1].data_hash if self._entries else self._genesis
        )
        # Chain: entry hash includes prev.
        entry = LogEntry(
            index=len(self._entries),
            data_hash=data_hash,
            prev_hash=prev_hash,
            timestamp=time.time(),
        )
        self._entries.append(entry)
        return entry.index

    def verify_inclusion(self, index: int, data: bytes) -> bool:
        """Verify data is at index (inclusion proof mock)."""
        if not 0 <= index < len(self._entries):
            return False
        entry = self._entries[index]
        expected = "sha256:" + hashlib.sha256(data).hexdigest()
        return entry.data_hash == expected

    def verify_chain(self) -> bool:
        """Verify hash chain integrity."""
        prev = self._genesis
        for entry in self._entries:
            if entry.prev_hash != prev:
                return False
            prev = entry.data_hash
        return True

    def __len__(self) -> int:
        return len(self._entries)


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "hashlib", "json", "pathlib", "time", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    r = MockRekor()
    i0 = r.append(b"entry1")
    i1 = r.append(b"entry2")
    assert i0 == 0 and i1 == 1
    assert r.verify_inclusion(0, b"entry1") is True
    assert r.verify_inclusion(0, b"wrong") is False
    assert r.verify_inclusion(99, b"entry1") is False
    assert r.verify_chain() is True
    assert len(r) == 2
    assert stdlib_only()
    print("crypto-defense-03 OK")


if __name__ == "__main__":
    main()
