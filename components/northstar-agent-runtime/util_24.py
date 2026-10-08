"""Diff helpers: unified diff, changed-line count, similarity. What this IS: text comparison plumbing. What this IS NOT: not a merge tool."""

from __future__ import annotations

import ast
import difflib

#: Module version.
UTIL_24_VERSION = "util-24.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-24.v1"


def unified(a: str, b: str, name_a="a", name_b="b") -> str:
    return "".join(
        difflib.unified_diff(
            a.splitlines(keepends=True), b.splitlines(keepends=True), name_a, name_b
        )
    )


def changed_lines(a: str, b: str) -> int:
    n = 0
    for line in unified(a, b).splitlines():
        if line.startswith(("+++", "---", "@@")):
            continue
        if line.startswith(("+", "-")):
            n += 1
    return n


def common_prefix(a: str, b: str) -> str:
    i = 0
    for ca, cb in zip(a, b):
        if ca != cb:
            break
        i += 1
    return a[:i]


def similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio()


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'difflib', 'pathlib']
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
    assert changed_lines("a\nb\n", "a\nc\n") == 2
    assert changed_lines("same", "same") == 0
    assert common_prefix("foobar", "foobaz") == "fooba"
    assert similarity("abc", "abc") == 1.0
    assert 0.0 <= similarity("abc", "xyz") < 0.5
    print("diff helpers OK")


if __name__ == "__main__":
    main()
