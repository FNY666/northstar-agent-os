"""Longest Valid Parentheses via index stack. IS: an index stack with a sentinel base for measuring valid spans. IS NOT: a DP table approach."""

from __future__ import annotations

import ast

VERSION = "stack-15.v1"

def _req_str(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _req_list(value: object, name: str) -> list:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a list")
    return list(value)

def longest_valid_parentheses(s: str) -> int:
    """Length of the longest valid parentheses substring.

    Fail-closed: only '(' and ')' allowed.
    """
    s = _req_str(s, "s")
    for ch in s:
        if ch not in "()":
            raise ValueError(f"invalid character {ch!r}")
    best = 0
    stack = [-1]
    for i, ch in enumerate(s):
        if ch == "(":
            stack.append(i)
        else:
            stack.pop()
            if not stack:
                stack.append(i)
            else:
                best = max(best, i - stack[-1])
    return best

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
    assert longest_valid_parentheses("(()") == 2
    assert longest_valid_parentheses(")()())") == 4
    assert longest_valid_parentheses("") == 0
    assert longest_valid_parentheses("()(())") == 6
    assert longest_valid_parentheses("(((") == 0
    try:
        longest_valid_parentheses("(a)")
    except ValueError:
        pass
    else:
        raise AssertionError("bad char must raise ValueError")
    assert stdlib_only()
    print("stack_15 OK")


if __name__ == "__main__":
    main()
