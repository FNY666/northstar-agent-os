"""Surrounded regions via union-find.

Union every border 'O' with a virtual outside node, plus adjacent 'O'
cells with each other. Any 'O' not connected to the virtual node is
surrounded and flipped to 'X'.
"""
import ast
import sys
from typing import List

UF_06_VERSION = "uf-06.v1"

class UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra

    def connected(self, a: int, b: int) -> bool:
        return self.find(a) == self.find(b)


def capture(board: List[List[str]]) -> List[List[str]]:
    """Flip surrounded 'O' regions to 'X'; return a new board."""
    if not board:
        return board
    rows, cols = len(board), len(board[0])
    uf = UnionFind(rows * cols + 1)
    top = rows * cols

    def idx(r: int, c: int) -> int:
        return r * cols + c

    for r in range(rows):
        for c in range(cols):
            if board[r][c] != "O":
                continue
            if r == 0 or r == rows - 1 or c == 0 or c == cols - 1:
                uf.union(idx(r, c), top)
            if r > 0 and board[r - 1][c] == "O":
                uf.union(idx(r, c), idx(r - 1, c))
            if c > 0 and board[r][c - 1] == "O":
                uf.union(idx(r, c), idx(r, c - 1))
    out = [row[:] for row in board]
    for r in range(rows):
        for c in range(cols):
            if out[r][c] == "O" and not uf.connected(idx(r, c), top):
                out[r][c] = "X"
    return out

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
    b = [["X", "X", "X", "X"], ["X", "O", "O", "X"],
         ["X", "X", "O", "X"], ["X", "O", "X", "X"]]
    assert capture(b) == [["X", "X", "X", "X"], ["X", "X", "X", "X"],
                          ["X", "X", "X", "X"], ["X", "O", "X", "X"]]
    assert capture([["O"]]) == [["O"]]
    assert capture([["X", "O"], ["O", "X"]]) == [["X", "O"], ["O", "X"]]
    assert capture([]) == []
    assert stdlib_only()
    print("uf-06 OK")


if __name__ == "__main__":
    main()
