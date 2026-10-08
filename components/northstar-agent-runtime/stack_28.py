"""Minimum Remove to Make Valid Parentheses. IS: an index stack marking unmatched brackets for deletion. IS NOT: finding all minimal-removal variants; returns one valid result."""

from __future__ import annotations

import ast

VERSION = "stack-28.v1"

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

def min_remove_to_make_valid(s: str) -> str:
    """Remove the fewest brackets so the rest is valid. Fail-closed."""
    s = _req_str(s, "s")
    chars = list(s)
    stack: list[int] = []
    for i, ch in enumerate(chars):
        if ch == "(":
            stack.append(i)
        elif ch == ")":
            if stack:
                stack.pop()
            else:
                chars[i] = ""
    for i in stack:
        chars[i] = ""
    return "".join(chars)

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
    assert min_remove_to_make_valid("lee(t(c)o)de)") == "lee(t(c)o)de"
    assert min_remove_to_make_valid("a)b(c)d") == "ab(c)d"
    assert min_remove_to_make_valid("))((") == ""
    assert min_remove_to_make_valid("(a(b(c)d)") == "a(b(c)d)"
    assert min_remove_to_make_valid("abc") == "abc"
    try:
        min_remove_to_make_valid(7)
    except ValueError:
        pass
    else:
        raise AssertionError("non-string must raise ValueError")
    assert stdlib_only()
    print("stack_28 OK")


if __name__ == "__main__":
    main()
