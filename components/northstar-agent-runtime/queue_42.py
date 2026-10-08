"""word_ladder_length: shortest transformation sequence length via BFS over one-letter edits. IS: a sequence length or 0 when unreachable; mismatched word lengths raise ValueError. IS NOT: a bidirectional BFS (this is the single-ended queue version)."""

from __future__ import annotations

import ast
from collections import deque
from typing import List
VERSION = "queue-42.v1"

def word_ladder_length(begin: str, end: str, word_list: List[str]) -> int:
    """Return the length of the shortest begin -> end ladder, else 0."""
    if not isinstance(begin, str) or not isinstance(end, str) or not begin or not end:
        raise ValueError("begin and end must be non-empty strings")
    if not isinstance(word_list, list):
        raise ValueError("word_list must be a list")
    words = set(word_list)
    if any(not isinstance(w, str) or len(w) != len(begin) for w in words):
        raise ValueError("all words must be strings of begin-word length")
    if len(end) != len(begin):
        raise ValueError("end must match begin length")
    if begin == end:
        return 1
    if end not in words:
        return 0
    q: deque = deque([(begin, 1)])
    seen = {begin}
    alpha = "abcdefghijklmnopqrstuvwxyz"
    while q:
        word, steps = q.popleft()
        for i in range(len(word)):
            for ch in alpha:
                nxt = word[:i] + ch + word[i + 1 :]
                if nxt == end:
                    return steps + 1
                if nxt in words and nxt not in seen:
                    seen.add(nxt)
                    q.append((nxt, steps + 1))
    return 0


def stdlib_only() -> bool:
    """AST-check: every import in this file resolves to the standard library."""
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing", "collections"}
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
    wl = ["hot", "dot", "dog", "lot", "log", "cog"]
    assert word_ladder_length("hit", "cog", wl) == 5
    assert word_ladder_length("hit", "cog", ["hot", "dot"]) == 0
    assert word_ladder_length("hit", "hit", wl) == 1
    assert word_ladder_length("a", "c", ["a", "b", "c"]) == 2
    try:
        word_ladder_length("hit", "cog", ["hot", "dots"])
    except ValueError:
        pass
    else:
        raise AssertionError("mismatched word length must raise ValueError")
    try:
        word_ladder_length("", "cog", wl)
    except ValueError:
        pass
    else:
        raise AssertionError("empty begin must raise ValueError")
    assert stdlib_only()
    print("queue-42 OK: BFS word ladder")


if __name__ == "__main__":
    main()
