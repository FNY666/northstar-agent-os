"""Top K Frequent Words: k most frequent words with lexicographic tie-break IS: min-heap of (-count, word) IS NOT: a full sort by frequency"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-37.v1"

def _req_inputs(words, k):
    if not isinstance(words, list) or not words:
        raise ValueError("words must be a non-empty list")
    for i, w in enumerate(words):
        if not isinstance(w, str):
            raise ValueError(f"words[{i}] must be a string")
    freq = {}
    for w in words:
        freq[w] = freq.get(w, 0) + 1
    if isinstance(k, bool) or not isinstance(k, int) or not 1 <= k <= len(freq):
        raise ValueError("k must satisfy 1 <= k <= distinct words")
    return list(words), k, freq


def top_k_frequent_words(words, k):
    """Return the k most frequent words, ties broken lexicographically.

    Fail-closed: bad input raises :class:`ValueError`.
    """
    words, k, freq = _req_inputs(words, k)
    heap = [(-c, w) for w, c in freq.items()]
    heapq.heapify(heap)
    return [heapq.heappop(heap)[1] for _ in range(k)]

def stdlib_only() -> bool:
    """AST-check: no imports outside the allowed stdlib set."""
    import pathlib

    allowed = {"__future__", "ast", "heapq", "pathlib", "typing"}
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
    assert top_k_frequent_words(["i", "love", "leetcode", "i", "love", "coding"], 2) == ["i", "love"]
    assert top_k_frequent_words(["the", "day", "is", "sunny", "the", "the", "the", "sunny", "is", "is"], 4) == ["the", "is", "sunny", "day"]
    assert top_k_frequent_words(["a"], 1) == ["a"]
    try:
        top_k_frequent_words([], 1)
    except ValueError:
        pass
    else:
        raise AssertionError("empty words must raise ValueError")
    assert stdlib_only()
    print("heap-37.v1 OK")


if __name__ == "__main__":
    main()
