"""Decode string: stack-based k[encoded] expansion.

Pushes (prefix, repeat) on '[', expands on ']'; handles nesting and multi-digit k.

What this IS: a real O(n) stack implementation.
What this IS NOT: streaming decode.
"""

from __future__ import annotations

import ast

#: Module version.
STR_48_VERSION = "str-decode.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-decode-string.v1"


class StrError(Exception):
    """Fail-closed."""


def decode_string(s: str) -> str:
    """Decode e.g. '3[a2[c]]' -> 'accaccacc'."""
    stack = []
    cur = ""
    num = 0
    for ch in s:
        if ch.isdigit():
            num = num * 10 + int(ch)
        elif ch == "[":
            stack.append((cur, num))
            cur = ""
            num = 0
        elif ch == "]":
            prev, k = stack.pop()
            cur = prev + cur * k
        else:
            cur += ch
    if stack:
        raise StrError("unbalanced brackets")
    return cur


def test_dec_basic():
    assert decode_string("3[a]2[bc]") == "aaabcbc"


def test_dec_nested():
    assert decode_string("3[a2[c]]") == "accaccacc"


def test_dec_empty():
    assert decode_string("") == ""


def test_dec_multi():
    assert decode_string("10[a]") == "a" * 10


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    test_dec_basic()
    test_dec_nested()
    test_dec_empty()
    test_dec_multi()
    assert stdlib_only()
    print("str-48 OK: decode")


if __name__ == "__main__":
    main()
