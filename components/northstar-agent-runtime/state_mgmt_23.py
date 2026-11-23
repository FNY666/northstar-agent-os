"""State 23: conflict resolution strategies.

Pluggable resolvers over conflicting writes.  Each write is a
Candidate(value, timestamp, node):
- "lww": highest (timestamp, node) wins
- "max": lexicographically/numerically greatest value wins
- "min": smallest value wins
- "union": merge all values into a sorted tuple (multi-value outcome)
- "first": earliest (timestamp, node) wins (first-write-wins)

resolve(strategy, candidates) -> Resolution(winner(s), strategy).

Deterministic: ties broken by node id, so every replica picks the
same winner.

Fail-closed: empty candidates, unknown strategy, malformed
candidates, or incomparable value types for max/min raise.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, List, Tuple


MODULE_VERSION = "state-mgmt-23.v1"
SCHEMA_PIN = "northstar.state-mgmt-23.v1"


class ConflictError(Exception):
    pass


@dataclass(frozen=True)
class Candidate:
    value: Any
    timestamp: int
    node: str

    def __post_init__(self):
        if not isinstance(self.timestamp, int) or isinstance(self.timestamp, bool) \
                or self.timestamp < 0:
            raise ConflictError("timestamp must be non-negative int")
        if not self.node:
            raise ConflictError("node required")


@dataclass(frozen=True)
class Resolution:
    strategy: str
    winners: Tuple[Any, ...]


STRATEGIES = ("lww", "max", "min", "union", "first")


def resolve(strategy: str, candidates: List[Candidate]) -> Resolution:
    if strategy not in STRATEGIES:
        raise ConflictError(f"unknown strategy {strategy!r}")
    if not candidates:
        raise ConflictError("candidates required")
    for c in candidates:
        if not isinstance(c, Candidate):
            raise ConflictError("candidates must be Candidate")
    if strategy == "lww":
        best = max(candidates, key=lambda c: (c.timestamp, c.node))
        return Resolution(strategy, (best.value,))
    if strategy == "first":
        best = min(candidates, key=lambda c: (c.timestamp, c.node))
        return Resolution(strategy, (best.value,))
    if strategy == "max":
        try:
            best = max(c.value for c in candidates)
        except TypeError as e:
            raise ConflictError(f"max needs comparable values: {e}") from e
        return Resolution(strategy, (best,))
    if strategy == "min":
        try:
            best = min(c.value for c in candidates)
        except TypeError as e:
            raise ConflictError(f"min needs comparable values: {e}") from e
        return Resolution(strategy, (best,))
    # union
    winners = tuple(sorted({repr(c.value) for c in candidates}))
    return Resolution(strategy, winners)


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for x in node.names:
                if x.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    cs = [Candidate("a", 1, "n1"), Candidate("b", 2, "n2"), Candidate("c", 2, "n3")]
    assert resolve("lww", cs).winners == ("c",)      # tie ts -> higher node
    assert resolve("first", cs).winners == ("a",)
    assert resolve("max", cs).winners == ("c",)
    assert resolve("min", cs).winners == ("a",)
    assert resolve("union", cs).winners == ("'a'", "'b'", "'c'")
    # Deterministic across call order.
    assert resolve("lww", list(reversed(cs))) == resolve("lww", cs)
    # Fail-closed.
    for bad in (lambda: resolve("nope", cs),
                lambda: resolve("lww", []),
                lambda: resolve("max", [Candidate("a", 1, "n"), Candidate(1, 2, "m")])):
        try:
            bad()
            raise AssertionError("should raise")
        except ConflictError:
            pass
    assert stdlib_only()
    print("state_mgmt_23 OK: 5 strategies, deterministic, fail-closed")


if __name__ == "__main__":
    main()
