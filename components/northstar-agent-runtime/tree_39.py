"""Game tree: minimax with alpha-beta pruning. Stdlib only."""
from __future__ import annotations
from typing import List

class GNode:
    def __init__(self, value=None, children=None, maximizing: bool = True) -> None:
        self.value = value
        self.children: List["GNode"] = children or []
        self.maximizing = maximizing

def minimax(n: GNode, alpha=float("-inf"), beta=float("inf")) -> float:
    if not n.children: return n.value
    if n.maximizing:
        best = float("-inf")
        for c in n.children:
            best = max(best, minimax(c, alpha, beta))
            alpha = max(alpha, best)
            if beta <= alpha: break
        return best
    best = float("inf")
    for c in n.children:
        best = min(best, minimax(c, alpha, beta))
        beta = min(beta, best)
        if beta <= alpha: break
    return best

def main() -> None:
    # max( min(3,5), min(2,9) ) = max(3,2) = 3
    tree = GNode(children=[
        GNode(children=[GNode(3), GNode(5)], maximizing=False),
        GNode(children=[GNode(2), GNode(9)], maximizing=False),
    ], maximizing=True)
    assert minimax(tree) == 3
    assert minimax(GNode(7)) == 7
    # pruning still correct on deeper tree
    deep = GNode(children=[
        GNode(children=[GNode(children=[GNode(1), GNode(2)], maximizing=True)], maximizing=False),
    ], maximizing=True)
    assert minimax(deep) == 2
    print("tree_39 Game tree OK")

if __name__ == "__main__":
    main()
