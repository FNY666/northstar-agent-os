"""Longest common prefix: horizontal scan.

Shrinks the candidate prefix against each word; O(total chars).

What this IS: a real implementation.
What this IS NOT: vertical-scan variant (same complexity).
"""

from __future__ import annotations

import ast

#: Module version.
STR_45_VERSION = "str-lcprefix.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-longest-common-prefix.v1"


class StrError(Exception):
    """Fail-closed."""


def longest_common_prefix(strs: list) -> str:
    """Longest shared prefix of all strings ('' if none/empty input)."""
    if not strs:
        return ""
    pref = strs[0]
    for w in strs[1:]:
        i = 0
        while i < len(pref) and i < len(w) and pref[i] == w[i]:
            i += 1
        pref = pref[:i]
        if not pref:
            break
    return pref


def test_lcp_basic():
    assert longest_common_prefix(["flower", "flow", "flight"]) == "fl"


def test_lcp_none():
    assert longest_common_prefix(["dog", "racecar", "car"]) == ""


def test_lcp_empty():
    assert longest_common_prefix([]) == ""


def test_lcp_single():
    assert longest_common_prefix(["abc"]) == "abc"


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
    test_lcp_basic()
    test_lcp_none()
    test_lcp_empty()
    test_lcp_single()
    assert stdlib_only()
    print("str-45 OK: lcprefix")


if __name__ == "__main__":
    main()
