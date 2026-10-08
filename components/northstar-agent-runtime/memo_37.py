"""Memoized Stone Game: memoization example.

Optimal play score difference: max(piles[l] - diff(l+1, r), piles[r] - diff(l, r-1)). Positive means the first player wins. The (l, r) cache gives O(n^2).

What this IS: a real memoized optimal-play score difference with a first-wins wrapper.
What this IS NOT: a move-sequence reconstructor; the host picks the output shape.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_37_VERSION = "memo-stone-game.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-stone-game.v1"


class MemoError(Exception):
    """Fail-closed."""


def stone_diff(piles: tuple, l: int = 0, r: int | None = None, _cache: dict | None = None) -> int:
    """Memoized max score difference for the player to move on piles[l..r]."""
    if r is None:
        r = len(piles) - 1
    cache: dict = _cache if _cache is not None else {}
    key = (l, r)
    if key in cache:
        return cache[key]
    if l > r:
        cache[key] = 0
    else:
        cache[key] = max(
            piles[l] - stone_diff(piles, l + 1, r, cache),
            piles[r] - stone_diff(piles, l, r - 1, cache),
        )
    return cache[key]


def first_wins(piles: tuple) -> bool:
    """True when the first player can force a win."""
    return stone_diff(piles) > 0

def test_first_wins_true():
    assert first_wins((5, 3, 4, 5)) is True


def test_first_wins_single():
    assert first_wins((7,)) is True


def test_stone_diff_zero():
    assert stone_diff((1, 1)) == 0

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
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
    test_first_wins_true()
    test_first_wins_single()
    test_stone_diff_zero()
    assert stdlib_only()
    print("memo-37 OK: stone-game")


if __name__ == "__main__":
    main()
