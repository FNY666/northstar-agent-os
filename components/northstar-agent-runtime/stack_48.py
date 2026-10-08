"""Make The String Great by removing bad adjacent pairs. IS: a char stack cancelling same-letter opposite-case neighbours. IS NOT: case-insensitive deduplication."""

from __future__ import annotations

import ast

VERSION = "stack-48.v1"

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

def make_good(s: str) -> str:
    """Delete bad pairs (same letter, different case) until good.

    Fail-closed: letters only.
    """
    s = _req_str(s, "s")
    if not s.isalpha() and s:
        raise ValueError("s must contain letters only")
    stack: list[str] = []
    for ch in s:
        if stack and stack[-1] != ch and stack[-1].lower() == ch.lower():
            stack.pop()
        else:
            stack.append(ch)
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
    assert make_good("leEeetcode") == "leetcode"
    assert make_good("abBAcC") == ""
    assert make_good("s") == "s"
    assert make_good("") == ""
    assert make_good("aAbB") == ""
    try:
        make_good("a1")
    except ValueError:
        pass
    else:
        raise AssertionError("non-letter must raise ValueError")
    assert stdlib_only()
    print("stack_48 OK")


if __name__ == "__main__":
    main()
