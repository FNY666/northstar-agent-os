"""Topological sort variant: counting linear extensions via subset DP (T-09)."""
from __future__ import annotations
import ast

VERSION = "topo_09.v1"

def count_orders(graph):
    nodes = list(graph)
    n = len(nodes)
    idx = {u: i for i, u in enumerate(nodes)}
    pred = [0] * n
    for u in graph:
        for v in graph[u]:
            if v in idx:
                pred[idx[v]] |= 1 << idx[u]
    dp = [0] * (1 << n)
    dp[0] = 1
    for mask in range(1 << n):
        for i in range(n):
            if not (mask >> i) & 1 and (pred[i] & mask) == pred[i]:
                dp[mask | (1 << i)] += dp[mask]
    return dp[(1 << n) - 1]

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    assert count_orders({1: [2], 2: [3], 3: []}) == 1
    assert count_orders({"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []}) == 2
    assert count_orders({"a": [], "b": [], "c": []}) == 6
    assert count_orders({"a": ["b"], "b": ["a"]}) == 0
    assert stdlib_only()
    print("topo_09 OK")


if __name__ == "__main__":
    main()
