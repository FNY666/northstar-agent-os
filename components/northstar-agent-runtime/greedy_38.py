"""greedy_38: Huffman code lengths (simplified).

Repeatedly merge the two least frequent symbols; each merge deepens their code by one.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys
GREEDY_38_VERSION = "greedy-38.v1"


def huffman_code_lengths(freqs):
    """Return {symbol: code length} for an optimal prefix code.

    freqs: dict of symbol -> frequency.
    """
    import heapq
    if not freqs:
        return {}
    if len(freqs) == 1:
        return {s: 1 for s in freqs}
    heap = [(f, [s]) for s, f in freqs.items()]
    heapq.heapify(heap)
    depth = {s: 0 for s in freqs}
    while len(heap) > 1:
        f1, s1 = heapq.heappop(heap)
        f2, s2 = heapq.heappop(heap)
        for s in s1:
            depth[s] += 1
        for s in s2:
            depth[s] += 1
        heapq.heappush(heap, (f1 + f2, s1 + s2))
    return depth

def stdlib_only() -> bool:
    """Parse this file with ``ast`` and assert every import is a used stdlib module."""
    with open(__file__, encoding="utf-8") as f:
        source = f.read()
    tree = ast.parse(source)
    imported = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported[alias.asname or alias.name.split(".")[0]] = alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported[alias.asname or alias.name] = (node.module or "").split(".")[0]
    used = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
    for alias, top in imported.items():
        assert top in sys.stdlib_module_names, "non-stdlib import: %s" % top
        assert alias in used, "imported but unused: %s" % alias
    return True



def main() -> None:
    d = huffman_code_lengths({"a": 5, "b": 9, "c": 12, "d": 13, "e": 16, "f": 45})
    assert d == {"a": 4, "b": 4, "c": 3, "d": 3, "e": 3, "f": 1}
    assert huffman_code_lengths({}) == {}
    assert huffman_code_lengths({"x": 7}) == {"x": 1}
    assert huffman_code_lengths({"a": 1, "b": 1}) == {"a": 1, "b": 1}
    assert stdlib_only()
    print("greedy_38 OK")


if __name__ == "__main__":
    main()
