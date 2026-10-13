"""State 14: Lamport timestamps, Simulated.

Single scalar clock:
- tick(): local += 1
- receive(remote): local = max(local, remote) + 1
- order(a, b, node_a, node_b): total order via (time, node_id)

Gives a consistent total order of events across replicas (not true
causality — concurrent events are ordered arbitrarily but
deterministically).

Fail-closed: negative or non-int timestamps raise.
"""

from __future__ import annotations

import ast
from typing import Tuple

MODULE_VERSION = "state-mgmt-14.v1"
SCHEMA_PIN = "northstar.state-mgmt-14.v1"


class LamportError(Exception):
    pass


class LamportClock:
    def __init__(self, node_id: str) -> None:
        if not node_id:
            raise LamportError("node_id required")
        self.node_id = node_id
        self.time = 0

    def tick(self) -> int:
        self.time += 1
        return self.time

    def receive(self, remote: int) -> int:
        if not isinstance(remote, int) or isinstance(remote, bool):
            raise LamportError("remote must be int")
        if remote < 0:
            raise LamportError("remote must be >= 0")
        self.time = max(self.time, remote) + 1
        return self.time

    def stamp(self) -> Tuple[int, str]:
        return (self.time, self.node_id)


def order(a: Tuple[int, str], b: Tuple[int, str]) -> int:
    """-1 if a first, 1 if b first, 0 if identical."""
    for x, y in (a, b):
        if not isinstance(x, int) or isinstance(x, bool) or x < 0:
            raise LamportError("bad timestamp")
        if not y:
            raise LamportError("bad node id")
    if a == b:
        return 0
    return -1 if a < b else 1


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}
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
    a, b = LamportClock("a"), LamportClock("b")
    t1 = a.tick()          # 1
    t2 = b.receive(t1)      # max(0,1)+1 = 2
    t3 = a.receive(t2)      # max(1,2)+1 = 3
    assert (t1, t2, t3) == (1, 2, 3)
    # Total order is deterministic.
    assert order((2, "b"), (2, "a")) == 1   # a < b lexicographically
    assert order((1, "z"), (2, "a")) == -1
    assert order((5, "n"), (5, "n")) == 0
    # Bad remote -> fail-closed.
    try:
        a.receive(-1)
        raise AssertionError("should raise")
    except LamportError:
        pass
    try:
        a.receive("x")  # type: ignore
        raise AssertionError("should raise")
    except LamportError:
        pass
    assert stdlib_only()
    print("state_mgmt_14 OK: tick/receive/order, fail-closed")


if __name__ == "__main__":
    main()
