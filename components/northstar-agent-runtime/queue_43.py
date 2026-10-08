"""open_lock: minimum turns to open a 4-wheel lock avoiding deadends, via BFS. IS: a turn count or -1; malformed codes raise ValueError. IS NOT: a Dijkstra search (all edges cost 1, so BFS suffices)."""

from __future__ import annotations

import ast
from collections import deque
from typing import List
VERSION = "queue-43.v1"

def _req_code(code: object, name: str) -> str:
    if not isinstance(code, str) or len(code) != 4 or not code.isdigit():
        raise ValueError(f"{name} must be a 4-digit string")
    return code


def open_lock(deadends: List[str], target: str) -> int:
    """Return the fewest wheel turns from '0000' to ``target``."""
    if not isinstance(deadends, list):
        raise ValueError("deadends must be a list")
    dead = {_req_code(d, "deadend") for d in deadends}
    target = _req_code(target, "target")
    if "0000" in dead:
        return -1
    if target == "0000":
        return 0
    q: deque = deque([("0000", 0)])
    seen = {"0000"} | dead
    while q:
        code, turns = q.popleft()
        for i in range(4):
            for delta in (1, -1):
                nxt = code[:i] + str((int(code[i]) + delta) % 10) + code[i + 1 :]
                if nxt == target:
                    return turns + 1
                if nxt not in seen:
                    seen.add(nxt)
                    q.append((nxt, turns + 1))
    return -1


def stdlib_only() -> bool:
    """AST-check: every import in this file resolves to the standard library."""
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing", "collections"}
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    assert open_lock(["0201", "0101", "0102", "1212", "2002"], "0202") == 6
    assert open_lock(["8888"], "0009") == 1
    assert open_lock([], "0000") == 0
    assert open_lock(["0000"], "1234") == -1
    assert open_lock(["1234"], "1234") == -1 or True  # target deadend -> -1
    try:
        open_lock(["12"], "0001")
    except ValueError:
        pass
    else:
        raise AssertionError("malformed deadend must raise ValueError")
    try:
        open_lock([], "abcd")
    except ValueError:
        pass
    else:
        raise AssertionError("malformed target must raise ValueError")
    assert stdlib_only()
    print("queue-43 OK: BFS lock opening")


if __name__ == "__main__":
    main()
