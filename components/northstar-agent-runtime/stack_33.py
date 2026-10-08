"""Reverse Substrings Between Each Pair of Parentheses. IS: a char stack reversing segments as each ')' closes. IS NOT: a recursive rewrite; single left-to-right pass."""

from __future__ import annotations

import ast

VERSION = "stack-33.v1"

def _req_str(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _req_int_list(values: object, name: str) -> list[int]:
    if not isinstance(values, list):
        raise ValueError(f"{name} must be a list")
    for v in values:
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError(f"{name} must contain only ints")
    return list(values)

def reverse_parentheses(s: str) -> str:
    """Reverse every parenthesised segment, innermost first.

    Fail-closed: lowercase letters and balanced brackets only.
    """
    s = _req_str(s, "s")
    if not all(ch.islower() or ch in "()" for ch in s):
        raise ValueError("s must contain lowercase letters and brackets only")
    stack: list[str] = []
    for ch in s:
        if ch == ")":
            buf: list[str] = []
            while stack and stack[-1] != "(":
                buf.append(stack.pop())
            if not stack:
                raise ValueError("unbalanced parentheses")
            stack.pop()
            stack.extend(buf)
        else:
            stack.append(ch)
    if "(" in stack:
        raise ValueError("unbalanced parentheses")
    return "".join(stack)

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
    assert reverse_parentheses("(abcd)") == "dcba"
    assert reverse_parentheses("(u(love)i)") == "iloveu"
    assert reverse_parentheses("(ed(et(oc))el)") == "leetcode"
    assert reverse_parentheses("abc") == "abc"
    assert reverse_parentheses("") == ""
    try:
        reverse_parentheses("(ab")
    except ValueError:
        pass
    else:
        raise AssertionError("unbalanced must raise ValueError")
    assert stdlib_only()
    print("stack_33 OK")


if __name__ == "__main__":
    main()
