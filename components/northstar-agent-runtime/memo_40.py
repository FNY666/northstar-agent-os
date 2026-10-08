"""Memoized Egg Drop: memoization example.

Min worst-case drops: 1 + min over floors x of max(egg_drop(e-1, x-1), egg_drop(e, f-x)). The (eggs, floors) cache gives O(e * f^2).

What this IS: a real memoized egg-drop solver, fail-closed on eggs < 1 or floors < 0.
What this IS NOT: a moves-based reformulation; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_40_VERSION = "memo-egg-drop.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-egg-drop.v1"


class MemoError(Exception):
    """Fail-closed."""


def egg_drop(eggs: int, floors: int, _cache: dict | None = None) -> int:
    """Memoized egg-drop min worst-case drops. Fail-closed on eggs < 1 or floors < 0."""
    if eggs < 1 or floors < 0:
        raise MemoError("egg_drop needs eggs >= 1 and floors >= 0")
    cache: dict = _cache if _cache is not None else {}
    key = (eggs, floors)
    if key in cache:
        return cache[key]
    if floors <= 1:
        cache[key] = floors
    elif eggs == 1:
        cache[key] = floors
    else:
        cache[key] = 1 + min(
            max(egg_drop(eggs - 1, x - 1, cache), egg_drop(eggs, floors - x, cache))
            for x in range(1, floors + 1)
        )
    return cache[key]

def test_egg_drop_example():
    assert egg_drop(2, 10) == 4


def test_egg_drop_one_egg():
    assert egg_drop(1, 5) == 5


def test_egg_drop_invalid_raises():
    try:
        egg_drop(0, 5)
    except MemoError:
        return
    raise AssertionError("expected MemoError")

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
    test_egg_drop_example()
    test_egg_drop_one_egg()
    test_egg_drop_invalid_raises()
    assert stdlib_only()
    print("memo-40 OK: egg-drop")


if __name__ == "__main__":
    main()
