"""Suffix automaton: linear substring structure.

Online SAM construction; counts distinct substrings and answers substring queries in O(|t|).

What this IS: a real SAM with clone states.
What this IS NOT: occurrence counting per state.
"""

from __future__ import annotations

import ast

#: Module version.
STR_27_VERSION = "str-sam.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-suffix-automaton.v1"


class StrError(Exception):
    """Fail-closed."""


class SuffixAutomaton:
    """Suffix automaton built by extending one char at a time."""

    def __init__(self, s: str = "") -> None:
        self.next = [{}]
        self.link = [-1]
        self.length = [0]
        self.last = 0
        for ch in s:
            self.extend(ch)

    def extend(self, ch: str) -> None:
        p = self.last
        cur = len(self.next)
        self.next.append({})
        self.link.append(0)
        self.length.append(self.length[p] + 1)
        while p != -1 and ch not in self.next[p]:
            self.next[p][ch] = cur
            p = self.link[p]
        if p == -1:
            self.link[cur] = 0
        else:
            q = self.next[p][ch]
            if self.length[p] + 1 == self.length[q]:
                self.link[cur] = q
            else:
                clone = len(self.next)
                self.next.append(dict(self.next[q]))
                self.link.append(self.link[q])
                self.length.append(self.length[p] + 1)
                while p != -1 and self.next[p].get(ch) == q:
                    self.next[p][ch] = clone
                    p = self.link[p]
                self.link[q] = self.link[cur] = clone
        self.last = cur

    def distinct_substrings(self) -> int:
        """Count distinct substrings of the built string."""
        return sum(self.length[v] - self.length[self.link[v]] for v in range(1, len(self.next)))

    def contains(self, t: str) -> bool:
        """True iff t is a substring."""
        v = 0
        for ch in t:
            if ch not in self.next[v]:
                return False
            v = self.next[v][ch]
        return True


def test_sam_distinct():
    assert SuffixAutomaton("ababa").distinct_substrings() == 9


def test_sam_contains():
    sam = SuffixAutomaton("banana")
    assert sam.contains("ana") is True
    assert sam.contains("nab") is False


def test_sam_empty():
    assert SuffixAutomaton("").distinct_substrings() == 0


def test_sam_single():
    assert SuffixAutomaton("a").distinct_substrings() == 1


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
    test_sam_distinct()
    test_sam_contains()
    test_sam_empty()
    test_sam_single()
    assert stdlib_only()
    print("str-27 OK: sam")


if __name__ == "__main__":
    main()
