"""is_subsequence (two-pointer), subsequence test of s inside t. IS: exact linear scan checking s is a subsequence of t. IS NOT: a substring test; characters of s need not be contiguous in t."""
from __future__ import annotations

import ast

VERSION = "twop-34.v1"


def is_subsequence(s: str, t: str) -> bool:
    if not isinstance(s, str) or not isinstance(t, str):
        raise ValueError("s and t must be strings")
    i = 0
    for ch in t:
        if i < len(s) and s[i] == ch:
            i += 1
    return i == len(s)


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
    assert is_subsequence("abc", "ahbgdc") is True
    assert is_subsequence("axc", "ahbgdc") is False
    assert is_subsequence("", "anything") is True  # edge: empty s always matches
    assert is_subsequence("", "") is True
    assert is_subsequence("longer", "short") is False
    try:
        is_subsequence("a", 5)  # type: ignore[arg-type]
    except ValueError:
        pass
    else:
        raise AssertionError("non-string t must raise ValueError")
    assert stdlib_only()
    print("twop_34 OK")


if __name__ == "__main__":
    main()
