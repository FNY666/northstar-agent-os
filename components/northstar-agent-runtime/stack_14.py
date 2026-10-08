"""Valid Parenthesis String with '*' wildcards. IS: a greedy range of possible open counts treating '*' as ( or ) or empty. IS NOT: a backtracking search; linear time via min/max open tracking."""

from __future__ import annotations

import ast

VERSION = "stack-14.v1"

def _req_str(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _req_list(value: object, name: str) -> list:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a list")
    return list(value)

def check_valid_star(s: str) -> bool:
    """True iff ``s`` can be balanced with '*' as '(', ')' or empty.

    Fail-closed: only '(', ')' and '*' allowed.
    """
    s = _req_str(s, "s")
    for ch in s:
        if ch not in "()_*":
            if ch != "*":
                raise ValueError(f"invalid character {ch!r}")
    lo = hi = 0
    for ch in s:
        if ch == "(":
            lo += 1
            hi += 1
        elif ch == ")":
            lo -= 1
            hi -= 1
        else:
            lo -= 1
            hi += 1
        if hi < 0:
            return False
        lo = max(lo, 0)
    return lo == 0

def stdlib_only() -> bool:
    """AST-check: no imports outside the allowed stdlib set."""
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing"}
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
    assert check_valid_star("()") is True
    assert check_valid_star("(*)") is True
    assert check_valid_star("(*))") is True
    assert check_valid_star("(((******))") is True
    assert check_valid_star("(()(") is False
    assert check_valid_star("") is True
    try:
        check_valid_star("(a)")
    except ValueError:
        pass
    else:
        raise AssertionError("bad char must raise ValueError")
    assert stdlib_only()
    print("stack_14 OK")


if __name__ == "__main__":
    main()
