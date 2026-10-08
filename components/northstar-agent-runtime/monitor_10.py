"""Threat intel feeds: mock IOC list, Simulated.

An in-memory threat-intel feed of indicators of compromise (IOC):
ip, domain, url, hash (sha256/md5). Each IOC carries a source,
confidence, first/last seen, and expiry (TTL). Expired IOCs are
purged on access.

What this IS: the feed store that monitor_11 (IOC matching) queries.

What this IS NOT:
* Not a live feed client -- host ingests real feeds into this store.
"""

from __future__ import annotations

import ast
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

#: Module version.
MONITOR_10_VERSION = "monitor-10.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.monitor-10.v1"

_VALID_TYPES = {"ip", "domain", "url", "hash"}


class IntelError(Exception):
    """Fail-closed."""


def _valid_value(ioc_type: str, value: str) -> bool:
    if ioc_type == "ip":
        parts = value.split(".")
        return len(parts) == 4 and all(
            p.isdigit() and 0 <= int(p) <= 255 for p in parts
        )
    if ioc_type == "domain":
        return bool(re.fullmatch(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?", value.lower()))
    if ioc_type == "url":
        return value.startswith(("http://", "https://"))
    if ioc_type == "hash":
        return len(value) in (32, 40, 64) and all(
            c in "0123456789abcdef" for c in value.lower()
        )
    return False


@dataclass
class Ioc:
    ioc_type: str
    value: str
    source: str
    confidence: int = 50  # 0-100
    first_seen_ns: int = field(default_factory=time.time_ns)
    last_seen_ns: int = field(default_factory=time.time_ns)
    ttl_s: int = 86400

    def __post_init__(self) -> None:
        if self.ioc_type not in _VALID_TYPES:
            raise IntelError(f"bad ioc type {self.ioc_type!r}")
        if not _valid_value(self.ioc_type, self.value):
            raise IntelError(f"bad value {self.value!r} for {self.ioc_type}")
        if not self.source:
            raise IntelError("source required")
        if not 0 <= self.confidence <= 100:
            raise IntelError("confidence must be 0-100")
        if self.ttl_s <= 0:
            raise IntelError("ttl_s must be positive")

    def expired(self, now_ns: Optional[int] = None) -> bool:
        now = now_ns if now_ns is not None else time.time_ns()
        return now - self.last_seen_ns > self.ttl_s * 1_000_000_000

    def key(self) -> str:
        return f"{self.ioc_type}:{self.value.lower()}"


class IntelFeed:
    """Mutable IOC store with expiry."""

    def __init__(self, name: str) -> None:
        if not name:
            raise IntelError("feed name required")
        self._name = name
        self._iocs: Dict[str, Ioc] = {}

    def add(self, ioc: Ioc) -> None:
        if not isinstance(ioc, Ioc):
            raise IntelError("ioc must be Ioc")
        key = ioc.key()
        existing = self._iocs.get(key)
        if existing is None or ioc.last_seen_ns > existing.last_seen_ns:
            self._iocs[key] = ioc

    def remove(self, ioc_type: str, value: str) -> bool:
        key = f"{ioc_type}:{value.lower()}"
        return self._iocs.pop(key, None) is not None

    def purge_expired(self) -> int:
        before = len(self._iocs)
        self._iocs = {k: v for k, v in self._iocs.items() if not v.expired()}
        return before - len(self._iocs)

    def list(self, ioc_type: Optional[str] = None) -> List[Ioc]:
        if ioc_type is not None and ioc_type not in _VALID_TYPES:
            raise IntelError(f"bad ioc type {ioc_type!r}")
        self.purge_expired()
        return [
            v for v in self._iocs.values()
            if ioc_type is None or v.ioc_type == ioc_type
        ]

    def count(self) -> int:
        self.purge_expired()
        return len(self._iocs)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "re", "time", "typing"}
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
    feed = IntelFeed("test")
    feed.add(Ioc("ip", "1.2.3.4", "src-a", confidence=90))
    feed.add(Ioc("domain", "evil.example", "src-b"))
    assert feed.count() == 2
    assert feed.remove("ip", "1.2.3.4") is True
    assert feed.count() == 1
    old = Ioc("hash", "ab" * 32, "src", ttl_s=1)
    old.last_seen_ns = time.time_ns() - 5_000_000_000  # 5s ago
    feed.add(old)
    assert feed.purge_expired() == 1
    assert feed.count() == 1
    try:
        Ioc("ip", "999.1.1.1", "s")
        raise AssertionError("should raise")
    except IntelError:
        pass
    try:
        Ioc("bogus", "x", "s")
        raise AssertionError("should raise")
    except IntelError:
        pass
    try:
        feed.list("bogus")
        raise AssertionError("should raise")
    except IntelError:
        pass
    assert stdlib_only()
    print("monitor-10 OK: IOC store, expiry, fail-closed, stdlib")


if __name__ == "__main__":
    main()
