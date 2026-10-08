"""String compression: in-place style run compression.

LeetCode 443 style: 'aabcccccaaa' -> 'a2b1c5a3'; single chars keep count 1.

What this IS: a real compression function.
What this IS NOT: true in-place list mutation API.
"""

from __future__ import annotations

import ast

#: Module version.
STR_39_VERSION = "str-compress.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-string-compression.v1"


class StrError(Exception):
    """Fail-closed."""


def compress_string(s: str) -> str:
    """Compress runs: char followed by count (count 1 kept)."""
    if not s:
        return ""
    out = []
    i = 0
    while i < len(s):
        j = i
        while j < len(s) and s[j] == s[i]:
            j += 1
        out.append(s[i])
        out.append(str(j - i))
        i = j
    return "".join(out)


def test_compress_basic():
    assert compress_string("aabcccccaaa") == "a2b1c5a3"


def test_compress_norun():
    assert compress_string("abc") == "a1b1c1"


def test_compress_empty():
    assert compress_string("") == ""


def test_compress_single():
    assert compress_string("a") == "a1"


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
    test_compress_basic()
    test_compress_norun()
    test_compress_empty()
    test_compress_single()
    assert stdlib_only()
    print("str-39 OK: compress")


if __name__ == "__main__":
    main()
