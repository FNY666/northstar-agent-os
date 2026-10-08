"""Suffix array (simplified): sorted list of suffix starting indices.

simplified: the straightforward O(n^2 log n) construction -- sort all
suffixes lexicographically and return their starting indices. This is
the naive baseline; production suffix arrays use O(n) or O(n log n)
prefix-doubling constructions, which this mock intentionally skips.

suffix_array(s) returns the list of indices i such that
s[i:] are in ascending lexicographic order. Empty string -> [].

Example: suffix_array("banana") -> [5, 3, 1, 0, 4, 2] because
"a" < "ana" < "anana" < "banana" < "na" < "nana".
"""

from __future__ import annotations

import ast
import sys
from typing import List

ALGO_39_VERSION = "algo-39.v1"


def suffix_array(s: str) -> List[int]:
    """Return starting indices of suffixes in lexicographic order."""
    return sorted(range(len(s)), key=lambda i: s[i:])


def stdlib_only() -> bool:
    """Assert every imported top-level module is from the stdlib."""
    src = open(__file__, encoding="utf-8").read()
    tree = ast.parse(src)
    stdlib = set(sys.stdlib_module_names)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in stdlib, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in stdlib, node.module
    return True


def main() -> None:
    assert suffix_array("") == []
    assert suffix_array("a") == [0]
    assert suffix_array("banana") == [5, 3, 1, 0, 4, 2]
    assert suffix_array("mississippi") == [10, 7, 4, 1, 0, 9, 8, 6, 3, 5, 2]
    # General invariant: suffixes are lexicographically sorted.
    s = "abracadabra"
    sa = suffix_array(s)
    assert sorted(sa) == list(range(len(s)))
    assert [s[i:] for i in sa] == sorted(s[i:] for i in range(len(s)))
    # Repeated characters.
    assert suffix_array("aaaa") == [3, 2, 1, 0]
    assert stdlib_only()
    print("algo_39 OK")


if __name__ == "__main__":
    main()
