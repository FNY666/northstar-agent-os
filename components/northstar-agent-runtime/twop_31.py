"""valid_palindrome_k_deletions (two-pointer), palindrome check with at most k deletions. IS: exact recursive two-pointer check with memoization. IS NOT: a general k-deletion solver. Simulated: exact only for k in 0..2; any other k raises ValueError rather than guessing."""
from __future__ import annotations

import ast

VERSION = "twop-31.v1"


def valid_palindrome_k_deletions(s: str, k: int) -> bool:
    if not isinstance(s, str):
        raise ValueError("s must be a string")
    if isinstance(k, bool) or not isinstance(k, int) or k < 0 or k > 2:
        raise ValueError("k must be an integer in 0..2 (exact only for k<=2)")
    memo: dict[tuple[int, int, int], bool] = {}

    def ok(lo: int, hi: int, remaining: int) -> bool:
        if lo >= hi:
            return True
        key = (lo, hi, remaining)
        if key in memo:
            return memo[key]
        if s[lo] == s[hi]:
            result = ok(lo + 1, hi - 1, remaining)
        elif remaining == 0:
            result = False
        else:
            result = ok(lo + 1, hi, remaining - 1) or ok(lo, hi - 1, remaining - 1)
        memo[key] = result
        return result

    return ok(0, len(s) - 1, k)


def stdlib_only() -> bool:
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing"}
    tree = ast.parse(pathlib.Path(__file__).read_text())
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
    assert valid_palindrome_k_deletions("racecar", 0) is True
    assert valid_palindrome_k_deletions("abca", 1) is True
    assert valid_palindrome_k_deletions("abc", 1) is False
    assert valid_palindrome_k_deletions("", 0) is True  # edge: empty string
    assert valid_palindrome_k_deletions("abc", 2) is True
    try:
        valid_palindrome_k_deletions("abc", 3)
    except ValueError:
        pass
    else:
        raise AssertionError("k=3 must raise ValueError")
    try:
        valid_palindrome_k_deletions("abc", -1)
    except ValueError:
        pass
    else:
        raise AssertionError("negative k must raise ValueError")
    assert stdlib_only()
    print("twop_31 OK")


if __name__ == "__main__":
    main()
