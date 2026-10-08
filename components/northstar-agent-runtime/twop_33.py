"""count_palindromic_substrings (two-pointer), count of all palindromic substrings. IS: exact O(n^2) expand-around-center counting every palindromic substring occurrence. IS NOT: a distinct-palindrome counter; duplicates count separately."""
from __future__ import annotations

import ast

VERSION = "twop-33.v1"


def count_palindromic_substrings(s: str) -> int:
    if not isinstance(s, str):
        raise ValueError("s must be a string")
    n = len(s)
    count = 0

    def expand(lo: int, hi: int) -> None:
        nonlocal count
        while lo >= 0 and hi < n and s[lo] == s[hi]:
            count += 1
            lo -= 1
            hi += 1

    for center in range(n):
        expand(center, center)  # odd length
        expand(center, center + 1)  # even length
    return count


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
    assert count_palindromic_substrings("abc") == 3
    assert count_palindromic_substrings("aaa") == 6
    assert count_palindromic_substrings("aba") == 4  # a, b, a, aba
    assert count_palindromic_substrings("") == 0  # edge: empty string
    assert count_palindromic_substrings("z") == 1
    try:
        count_palindromic_substrings(None)  # type: ignore[arg-type]
    except ValueError:
        pass
    else:
        raise AssertionError("non-string must raise ValueError")
    assert stdlib_only()
    print("twop_33 OK")


if __name__ == "__main__":
    main()
