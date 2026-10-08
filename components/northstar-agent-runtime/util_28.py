"""Regex helpers: length-capped compile, find groups, replace, split-keep. What this IS: safer regex entry points. What this IS NOT: not ReDoS-proof."""

from __future__ import annotations

import ast
import re

#: Module version.
UTIL_28_VERSION = "util-28.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-28.v1"


class RegexError(Exception):
    """Regex helper failure."""


def safe_compile(pattern: str, max_len=1000):
    if len(pattern) > max_len:
        raise RegexError(f"pattern too long: {len(pattern)} > {max_len}")
    try:
        return re.compile(pattern)
    except re.error as e:
        raise RegexError(f"bad pattern: {e}") from e


def find_groups(pattern: str, text: str):
    return safe_compile(pattern).findall(text)


def replace_all(text: str, pattern: str, repl: str) -> str:
    return safe_compile(pattern).sub(repl, text)


def split_keep(text: str, pattern: str):
    """Split but keep the separators."""
    return safe_compile(f"({pattern})").split(text)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'pathlib', 're']
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
    assert find_groups(r"(\d+)-(\d+)", "a1-2 b3-4") == [("1", "2"), ("3", "4")]
    assert replace_all("aaa", "a", "b") == "bbb"
    assert split_keep("a1b2", r"\d") == ["a", "1", "b", "2", ""]
    try:
        safe_compile("x" * 1001)
        raise AssertionError("should raise")
    except RegexError:
        pass
    print("regex helpers OK")


if __name__ == "__main__":
    main()
