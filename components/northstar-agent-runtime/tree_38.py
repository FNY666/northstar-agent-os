"""Decision tree (mock): ID3-style split on tiny categorical data. Stdlib only."""
from __future__ import annotations
import math
from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

@dataclass
class DNode:
    feature: Optional[int] = None
    branches: Optional[Dict[Any, "DNode"]] = None
    label: Optional[Any] = None

def _entropy(rows: List[tuple]) -> float:
    n = len(rows)
    if n == 0: return 0.0
    c = Counter(r[-1] for r in rows)
    return -sum((v / n) * math.log2(v / n) for v in c.values())

def _best_split(rows, features: List[int]):
    base = _entropy(rows)
    best, bg = None, 0.0
    for f in features:
        vals = set(r[f] for r in rows)
        gain = base - sum(
            len([r for r in rows if r[f] == v]) / len(rows) * _entropy([r for r in rows if r[f] == v])
            for v in vals)
        if gain > bg: best, bg = f, gain
    return best

def fit(rows: List[tuple], features: List[int]) -> DNode:
    labels = [r[-1] for r in rows]
    if len(set(labels)) == 1: return DNode(label=labels[0])
    if not features: return DNode(label=Counter(labels).most_common(1)[0][0])
    f = _best_split(rows, features)
    if f is None: return DNode(label=Counter(labels).most_common(1)[0][0])
    branches = {}
    rest = [x for x in features if x != f]
    for v in set(r[f] for r in rows):
        sub = [r for r in rows if r[f] == v]
        branches[v] = fit(sub, rest)
    return DNode(feature=f, branches=branches)

def predict(n: DNode, row: tuple):
    while n.label is None:
        n = n.branches[row[n.feature]]
    return n.label

def main() -> None:
    data = [("sunny", "hot", "no"), ("sunny", "mild", "no"),
            ("rain", "mild", "yes"), ("rain", "cool", "yes")]
    tree = fit(data, [0, 1])
    assert predict(tree, ("sunny", "hot")) == "no"
    assert predict(tree, ("rain", "cool")) == "yes"
    assert predict(tree, ("sunny", "mild")) == "no"
    print("tree_38 Decision tree (mock) OK")

if __name__ == "__main__":
    main()
