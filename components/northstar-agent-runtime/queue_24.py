"""card_reveal_order: initial deck order so that reveal-top/move-top-to-bottom yields 1..n. IS: a deck list for increasing reveal; n < 1 raises ValueError. IS NOT: the forward simulation (this is the inverse construction)."""

from __future__ import annotations

import ast
from collections import deque
from typing import List
VERSION = "queue-24.v1"

def card_reveal_order(n: int) -> List[int]:
    """Return the deck arrangement whose reveal order is ``1..n``."""
    if isinstance(n, bool) or not isinstance(n, int) or n < 1:
        raise ValueError("n must be a positive int")
    q: deque = deque()
    for card in range(n, 0, -1):
        if q:
            q.appendleft(q.pop())  # inverse of "move top to bottom"
        q.appendleft(card)  # inverse of "reveal top"
    return list(q)


def _reveal(deck: List[int]) -> List[int]:
    q: deque = deque(deck)
    out = []
    while q:
        out.append(q.popleft())
        if q:
            q.append(q.popleft())
    return out


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
    assert card_reveal_order(1) == [1]
    assert card_reveal_order(2) == [1, 2]
    assert card_reveal_order(3) == [1, 3, 2]
    assert card_reveal_order(5) == [1, 5, 2, 4, 3]
    for n in (1, 2, 3, 5, 8, 13):
        assert _reveal(card_reveal_order(n)) == list(range(1, n + 1))
    for bad in (0, -3, "5", 2.5, True):
        try:
            card_reveal_order(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"n={bad!r} must raise ValueError")
    assert stdlib_only()
    print("queue-24 OK: card reveal construction")


if __name__ == "__main__":
    main()
