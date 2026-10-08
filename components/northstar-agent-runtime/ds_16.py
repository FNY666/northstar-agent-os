"""DS: Suffix Trie (16/50). suffix trie

Mock: naive suffix-set backend: all suffixes are materialized in a set, so substring queries are correct but memory is O(n^2), not a compressed trie."""
from __future__ import annotations

import ast

#: Module version.
DS_16_VERSION = "ds-16-suffix-trie.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-16.suffix-trie.v1"


class SuffixTrie:
    """API-compatible suffix-trie stub (see module docstring)."""

    def __init__(self, text=""):
        self._suffixes = set()
        if text:
            self.build(text)

    def build(self, text):
        self._suffixes = {text[i:] for i in range(len(text))}

    def contains(self, pattern):
        if not pattern:
            return True
        return any(s.startswith(pattern) for s in self._suffixes)

    def suffix_count(self):
        return len(self._suffixes)

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
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
    st = SuffixTrie("banana")
    assert st.contains("ana") is True
    assert st.contains("nan") is True
    assert st.contains("apple") is False
    assert st.suffix_count() == 6
    assert stdlib_only()
    print("ds-16 OK: substring queries via suffix set")


if __name__ == "__main__":
    main()
