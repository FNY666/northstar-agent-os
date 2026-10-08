"""Range Add Character Frequency: difference array example.

26 alphabet counters with range adds: add v to every letter in [l, r]; point-query any letter's total.

What this IS: a real alphabet-indexed difference array, fail-closed on bad ranges
What this IS NOT: a 26-element array updated elementwise per query
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_11_VERSION = "range-add-char-freq.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-range-add-char-freq.v1"


class DiffError(Exception):
    """Fail-closed."""


class CharFreqDiff:
    """Range adds over alphabet indices 0..25; point query per letter."""

    def __init__(self):
        self._diff = [0] * 27

    def add(self, l: int, r: int, v: int) -> None:
        if not (0 <= l <= r < 26) or v < 0:
            raise DiffError("bad range or negative v")
        self._diff[l] += v
        self._diff[r + 1] -= v

    def counts(self) -> list:
        out = []
        cur = 0
        for i in range(26):
            cur += self._diff[i]
            out.append(cur)
        return out

    def query(self, ch: str) -> int:
        i = ord(ch) - 97
        if not (0 <= i < 26):
            raise DiffError("ch must be a-z")
        return self.counts()[i]

def test_basic():
    c = CharFreqDiff()
    c.add(0, 2, 3)
    assert c.query("a") == 3
    assert c.query("c") == 3
    assert c.query("d") == 0


def test_overlap():
    c = CharFreqDiff()
    c.add(0, 2, 3)
    c.add(1, 1, 2)
    assert c.query("b") == 5
    assert sum(c.counts()) == 11


def test_bad_range():
    c = CharFreqDiff()
    try:
        c.add(2, 1, 1)
    except DiffError:
        return
    raise AssertionError("expected DiffError")


def test_bad_char():
    c = CharFreqDiff()
    try:
        c.query("A")
    except DiffError:
        return
    raise AssertionError("expected DiffError")

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
    test_basic()
    test_overlap()
    test_bad_range()
    test_bad_char()
    assert stdlib_only()
    print("diff-11 OK: range-add-char-freq")


if __name__ == "__main__":
    main()
