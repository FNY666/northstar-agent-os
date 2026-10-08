"""Backspace String Compare via typed-character stacks. IS: two stacks simulating '#' deletes, then comparing results. IS NOT: a two-pointer in-place variant."""

from __future__ import annotations

import ast

VERSION = "stack-13.v1"

def _req_str(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _req_list(value: object, name: str) -> list:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a list")
    return list(value)

def _apply(s: str) -> str:
    stack: list[str] = []
    for ch in s:
        if ch == "#":
            if stack:
                stack.pop()
        else:
            stack.append(ch)
    return "".join(stack)


def backspace_compare(s: str, t: str) -> bool:
    """True iff ``s`` and ``t`` match after backspaces. Fail-closed."""
    s = _req_str(s, "s")
    t = _req_str(t, "t")
    return _apply(s) == _apply(t)

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
    assert backspace_compare("ab#c", "ad#c") is True
    assert backspace_compare("ab##", "c#d#") is True
    assert backspace_compare("a#c", "b") is False
    assert backspace_compare("###", "") is True
    try:
        backspace_compare("a", 5)
    except ValueError:
        pass
    else:
        raise AssertionError("non-string must raise ValueError")
    assert stdlib_only()
    print("stack_13 OK")


if __name__ == "__main__":
    main()
