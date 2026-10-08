"""bag_of_tokens_score (two-pointer), max score achievable with tokens and power. IS: the greedy model - play cheapest token face-up to gain score, sacrifice most expensive face-down to regain power; never wrong to trade when it yields net gain. IS NOT: an exhaustive search over play sequences."""
from __future__ import annotations

import ast

VERSION = "twop-45.v1"


def bag_of_tokens_score(tokens: list[int], power: int) -> int:
    """Return the max score obtainable from tokens with initial power."""
    if not isinstance(tokens, list):
        raise ValueError("tokens must be a list")
    for t in tokens:
        if isinstance(t, bool) or not isinstance(t, int) or t < 0:
            raise ValueError("tokens must be non-negative ints")
    if isinstance(power, bool) or not isinstance(power, int):
        raise ValueError("power must be an int")
    if power < 0:
        raise ValueError("power must be non-negative")
    ordered = sorted(tokens)
    left = 0
    right = len(ordered) - 1
    score = 0
    best = 0
    while left <= right:
        if power >= ordered[left]:
            power -= ordered[left]
            left += 1
            score += 1
            if score > best:
                best = score
        elif score > 0:
            power += ordered[right]
            right -= 1
            score -= 1
        else:
            break
    return best


def stdlib_only() -> bool:
    """AST-parse this file; return False if any import outside the allowed set appears."""
    import pathlib
    src = pathlib.Path(__file__).read_text()
    allowed = {"__future__", "ast", "pathlib", "typing"}
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    assert bag_of_tokens_score([100], 50) == 0
    assert bag_of_tokens_score([200, 100], 150) == 1
    assert bag_of_tokens_score([100, 200, 300, 400], 200) == 2
    assert bag_of_tokens_score([], 100) == 0  # edge: no tokens
    assert bag_of_tokens_score([100], 150) == 1
    try:
        bag_of_tokens_score([-1], 100)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for negative token")
    assert stdlib_only()
    print("bag_of_tokens_score OK")


if __name__ == "__main__":
    main()
