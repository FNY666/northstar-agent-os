"""is_palindrome_queue: palindrome check by comparing both ends of a deque. IS: True/False for the string; non-string input raises ValueError. IS NOT: a case-insensitive or alphanumeric-skipping variant."""

from __future__ import annotations

import ast
from collections import deque
VERSION = "queue-26.v1"

def is_palindrome_queue(s: str) -> bool:
    """Return True iff ``s`` reads the same forwards and backwards."""
    if not isinstance(s, str):
        raise ValueError("s must be a string")
    q: deque = deque(s)
    while len(q) > 1:
        if q.popleft() != q.pop():
            return False
    return True


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
    assert is_palindrome_queue("racecar") is True
    assert is_palindrome_queue("hello") is False
    assert is_palindrome_queue("") is True
    assert is_palindrome_queue("a") is True
    assert is_palindrome_queue("ab") is False
    assert is_palindrome_queue("abba") is True
    try:
        is_palindrome_queue(12321)
    except ValueError:
        pass
    else:
        raise AssertionError("non-string must raise ValueError")
    assert stdlib_only()
    print("queue-26 OK: deque palindrome check")


if __name__ == "__main__":
    main()
