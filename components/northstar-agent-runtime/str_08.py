"""Aho-Corasick: linear multi-pattern matching.

Trie of patterns plus BFS-built failure links; scans text once in O(n + m + z) reporting every pattern hit.

What this IS: a real automaton with failure links.
What this IS NOT: a serialized/persistent automaton.
"""

from __future__ import annotations

import ast
from collections import deque

#: Module version.
STR_08_VERSION = "str-aho-corasick.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-aho-corasick.v1"


class StrError(Exception):
    """Fail-closed."""


class AhoCorasick:
    """Multi-pattern matcher: add patterns, then search text once."""

    def __init__(self, patterns) -> None:
        self.trie = [{}]
        self.fail = [0]
        self.out = [[]]
        for pat in patterns:
            node = 0
            for ch in pat:
                if ch not in self.trie[node]:
                    self.trie[node][ch] = len(self.trie)
                    self.trie.append({})
                    self.fail.append(0)
                    self.out.append([])
                node = self.trie[node][ch]
            self.out[node].append(pat)
        q = deque()
        for ch, nxt in self.trie[0].items():
            self.fail[nxt] = 0
            q.append(nxt)
        while q:
            r = q.popleft()
            for ch, u in self.trie[r].items():
                q.append(u)
                v = self.fail[r]
                while v and ch not in self.trie[v]:
                    v = self.fail[v]
                self.fail[u] = self.trie[v].get(ch, 0)
                self.out[u] += self.out[self.fail[u]]

    def search(self, text: str) -> list:
        """Return [(start, pattern)] for every match in text."""
        node = 0
        res = []
        for i, ch in enumerate(text):
            while node and ch not in self.trie[node]:
                node = self.fail[node]
            node = self.trie[node].get(ch, 0)
            for pat in self.out[node]:
                res.append((i - len(pat) + 1, pat))
        return res


def test_ac_classic():
    ac = AhoCorasick(["he", "she", "his", "hers"])
    assert set(ac.search("ushers")) == {(1, "she"), (2, "he"), (2, "hers")}


def test_ac_overlap():
    ac = AhoCorasick(["a", "aa"])
    assert set(ac.search("aaa")) == {(0, "a"), (1, "a"), (2, "a"), (0, "aa"), (1, "aa")}


def test_ac_none():
    ac = AhoCorasick(["xyz"])
    assert ac.search("abc") == []


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "collections", "pathlib"}
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
    test_ac_classic()
    test_ac_overlap()
    test_ac_none()
    assert stdlib_only()
    print("str-08 OK: aho-corasick")


if __name__ == "__main__":
    main()
