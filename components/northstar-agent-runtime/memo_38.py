"""Memoized Predict the Winner: memoization example.

Same optimal-play recurrence as stone game but the wrapper checks diff >= 0 (ties count as a win for player 1).

What this IS: a real memoized winner predictor with a >= 0 tie rule.
What this IS NOT: a stone-game clone for even piles only; the host picks the problem.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_38_VERSION = "memo-predict-winner.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-predict-winner.v1"


class MemoError(Exception):
    """Fail-closed."""


def winner_diff(nums: tuple, l: int = 0, r: int | None = None, _cache: dict | None = None) -> int:
    """Memoized max score difference for the player to move on nums[l..r]."""
    if r is None:
        r = len(nums) - 1
    cache: dict = _cache if _cache is not None else {}
    key = (l, r)
    if key in cache:
        return cache[key]
    if l == r:
        cache[key] = nums[l]
    else:
        cache[key] = max(
            nums[l] - winner_diff(nums, l + 1, r, cache),
            nums[r] - winner_diff(nums, l, r - 1, cache),
        )
    return cache[key]


def can_win(nums: tuple) -> bool:
    """True when player 1 can force at least a tie."""
    return winner_diff(nums) >= 0

def test_can_win_false():
    assert can_win((1, 5, 2)) is False


def test_can_win_true():
    assert can_win((1, 5, 233, 7)) is True


def test_can_win_single():
    assert can_win((3,)) is True

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
    test_can_win_false()
    test_can_win_true()
    test_can_win_single()
    assert stdlib_only()
    print("memo-38 OK: predict-winner")


if __name__ == "__main__":
    main()
