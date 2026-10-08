"""Decode String with nested k[encoded] repetitions. IS: a dual stack (counts + partial strings) handling nested brackets. IS NOT: a regex substitution; nesting depth is unbounded."""

from __future__ import annotations

import ast

VERSION = "stack-09.v1"

def _req_str(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _req_list(value: object, name: str) -> list:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a list")
    return list(value)

def decode_string(s: str) -> str:
    """Decode ``k[encoded]`` patterns, supporting nesting.

    Fail-closed: ``s`` must be a string; digits, letters and square
    brackets only; brackets must balance.
    """
    s = _req_str(s, "s")
    for ch in s:
        if not (ch.isdigit() or ch.isalpha() or ch in "[]"):
            raise ValueError(f"invalid character {ch!r}")
    counts: list[int] = []
    parts: list[str] = []
    cur = ""
    k = 0
    for ch in s:
        if ch.isdigit():
            k = k * 10 + int(ch)
        elif ch == "[":
            counts.append(k)
            parts.append(cur)
            cur = ""
            k = 0
        elif ch == "]":
            if not counts:
                raise ValueError("unbalanced brackets")
            cur = parts.pop() + cur * counts.pop()
        else:
            cur += ch
    if counts:
        raise ValueError("unbalanced brackets")
    return cur

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
    assert decode_string("3[a]2[bc]") == "aaabcbc"
    assert decode_string("3[a2[c]]") == "accaccacc"
    assert decode_string("2[abc]3[cd]ef") == "abcabccdcdcdef"
    assert decode_string("abc") == "abc"
    assert decode_string("") == ""
    assert decode_string("10[a]") == "a" * 10
    try:
        decode_string("3[a")
    except ValueError:
        pass
    else:
        raise AssertionError("unbalanced must raise ValueError")
    assert stdlib_only()
    print("stack_09 OK")


if __name__ == "__main__":
    main()
