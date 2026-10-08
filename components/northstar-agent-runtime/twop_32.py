"""longest_palindromic_substring (two-pointer), longest palindromic substring via expansion. IS: exact O(n^2) expand-around-center returning one longest palindromic substring. IS NOT: Manacher linear-time; ties break toward the earliest center."""
from __future__ import annotations

import ast

VERSION = "twop-32.v1"


def longest_palindromic_substring(s: str) -> str:
    if not isinstance(s, str):
        raise ValueError("s must be a string")
    n = len(s)
    if n <= 1:
        return s
    best_lo, best_hi = 0, 0

    def expand(lo: int, hi: int) -> None:
        nonlocal best_lo, best_hi
        while lo >= 0 and hi < n and s[lo] == s[hi]:
            if hi - lo > best_hi - best_lo:
                best_lo, best_hi = lo, hi
            lo -= 1
            hi += 1

    for center in range(n):
        expand(center, center)  # odd length
        expand(center, center + 1)  # even length
    return s[best_lo : best_hi + 1]


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
    assert longest_palindromic_substring("babad") in ("bab", "aba")
    assert longest_palindromic_substring("cbbd") == "bb"
    assert longest_palindromic_substring("racecar") == "racecar"
    assert longest_palindromic_substring("") == ""  # edge: empty string
    assert longest_palindromic_substring("x") == "x"
    try:
        longest_palindromic_substring(123)  # type: ignore[arg-type]
    except ValueError:
        pass
    else:
        raise AssertionError("non-string must raise ValueError")
    assert stdlib_only()
    print("twop_32 OK")


if __name__ == "__main__":
    main()
