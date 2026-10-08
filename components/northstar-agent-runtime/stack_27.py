"""Minimum Add to Make Parentheses Valid. IS: a counter acting as a stack: unmatched opens need closes and vice versa. IS NOT: inserting characters; only counts the insertions."""

from __future__ import annotations

import ast

VERSION = "stack-27.v1"

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

def min_add_to_make_valid(s: str) -> int:
    """Minimum insertions to balance. Fail-closed: only '(' and ')'."""
    s = _req_str(s, "s")
    for ch in s:
        if ch not in "()":
            raise ValueError(f"invalid character {ch!r}")
    opens = need = 0
    for ch in s:
        if ch == "(":
            opens += 1
        elif opens:
            opens -= 1
        else:
            need += 1
    return opens + need

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
    assert min_add_to_make_valid("())") == 1
    assert min_add_to_make_valid("(((") == 3
    assert min_add_to_make_valid("()") == 0
    assert min_add_to_make_valid("()))((") == 4
    assert min_add_to_make_valid("") == 0
    try:
        min_add_to_make_valid("(a)")
    except ValueError:
        pass
    else:
        raise AssertionError("bad char must raise ValueError")
    assert stdlib_only()
    print("stack_27 OK")


if __name__ == "__main__":
    main()
