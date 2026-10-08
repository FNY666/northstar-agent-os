"""Tripwires: mock file-integrity tripwires, Simulated.

Registers paths with expected sha256 hashes (host-supplied).
verify(current) compares a host-supplied current hash map:
- ok / changed / missing per registered path
- unexpected for paths present in current but not registered

What this IS: integrity comparison bookkeeping.

What this IS NOT:
* Not live FIM -- the host supplies both hash sets.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Dict

#: Module version.
MONITOR_22_VERSION = "monitor-22.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.monitor-22.v1"

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class TripwireError(Exception):
    """Fail-closed."""


def _check_hash(h: str) -> str:
    if not isinstance(h, str) or not _HEX64.match(h):
        raise TripwireError("hash must be 64 lowercase hex chars")
    return h


@dataclass
class TripwireSet:
    """Registered integrity baselines."""

    _base: Dict[str, str] = None  # type: ignore

    def __post_init__(self) -> None:
        if self._base is None:
            self._base = {}

    def add(self, path: str, expected_hash: str) -> None:
        if not path or not isinstance(path, str):
            raise TripwireError("path required")
        self._base[path] = _check_hash(expected_hash)

    def remove(self, path: str) -> None:
        if path not in self._base:
            raise TripwireError(f"unknown path {path!r}")
        del self._base[path]

    def verify(self, current: Dict[str, str]) -> Dict[str, str]:
        """Compare current hashes to baseline. Returns path -> status."""
        if not isinstance(current, dict):
            raise TripwireError("current must be dict")
        for h in current.values():
            _check_hash(h)
        result: Dict[str, str] = {}
        for path, expected in self._base.items():
            if path not in current:
                result[path] = "missing"
            elif current[path] != expected:
                result[path] = "changed"
            else:
                result[path] = "ok"
        for path in current:
            if path not in self._base:
                result[path] = "unexpected"
        return result

    def summary(self, current: Dict[str, str]) -> Dict[str, int]:
        counts: Dict[str, int] = {"ok": 0, "changed": 0, "missing": 0, "unexpected": 0}
        for status in self.verify(current).values():
            counts[status] += 1
        return counts


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "re", "typing"}
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
    tw = TripwireSet()
    h1 = "a" * 64
    h2 = "b" * 64
    tw.add("/etc/passwd", h1)
    tw.add("/etc/shadow", h2)
    r = tw.verify({"/etc/passwd": h1, "/etc/shadow": "c" * 64, "/tmp/new": h1})
    assert r == {
        "/etc/passwd": "ok",
        "/etc/shadow": "changed",
        "/tmp/new": "unexpected",
    }
    r = tw.verify({"/etc/passwd": h1})
    assert r["/etc/shadow"] == "missing"
    assert tw.summary({"/etc/passwd": h1, "/etc/shadow": h2}) == {
        "ok": 2, "changed": 0, "missing": 0, "unexpected": 0,
    }
    tw.remove("/etc/shadow")
    assert tw.verify({"/etc/passwd": h1}) == {"/etc/passwd": "ok"}
    for bad in (
        lambda: tw.add("", h1),
        lambda: tw.add("/x", "nothex"),
        lambda: tw.add("/x", "A" * 64),
        lambda: tw.remove("/nope"),
        lambda: tw.verify("nope"),  # type: ignore
        lambda: tw.verify({"/x": "zz"}),
    ):
        try:
            bad()
            raise AssertionError("should raise")
        except TripwireError:
            pass
    assert stdlib_only()
    print("monitor-22 OK: ok/changed/missing/unexpected, summary, fail-closed, stdlib")


if __name__ == "__main__":
    main()
