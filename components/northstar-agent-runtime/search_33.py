"""Beam search (mock), Simulated.

What this IS: mock layered search keeping the top-k states per layer.

What this IS NOT: mock/simplified simulation; narrow beams can miss the goal.
"""

from __future__ import annotations

import ast
from typing import Any, Callable, List, Optional

#: Module version.
SEARCH_33_VERSION = "search-33.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-33.v1"


class SearchError(Exception):
    """Fail-closed."""


def beam_search(start: Any, expand_fn: Callable[[Any], List[Any]],
                goal_fn: Callable[[Any], bool], score_fn: Callable[[Any], float],
                depth: int, beam_width: int) -> Optional[Any]:
    """Mock beam search: first goal state found, or None."""
    if expand_fn is None or goal_fn is None or score_fn is None:
        raise SearchError("args required")
    if beam_width < 1:
        raise SearchError("beam_width must be >= 1")
    if depth < 0:
        raise SearchError("depth must be >= 0")
    beam = [start]
    if goal_fn(start):
        return start
    for _ in range(depth):
        cands = []
        for s in beam:
            cands.extend(expand_fn(s))
        if not cands:
            return None
        cands.sort(key=score_fn)
        beam = cands[:beam_width]
        for s in beam:
            if goal_fn(s):
                return s
    return None

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "collections", "dataclasses", "heapq",
               "itertools", "math", "pathlib", "random", "typing"}
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
    exp = {"s": ["a", "b"], "a": ["G"], "b": ["c"], "c": ["d"]}
    score = {"s": 9, "a": 10, "b": 0, "G": 0, "c": 5, "d": 6}.__getitem__
    assert beam_search("s", exp.__getitem__, lambda x: x == "G", score, 4, 2) == "G"
    assert beam_search("s", exp.__getitem__, lambda x: x == "G", score, 4, 1) is None
    assert stdlib_only()
    print("search-33.v1 OK")


if __name__ == "__main__":
    main()
