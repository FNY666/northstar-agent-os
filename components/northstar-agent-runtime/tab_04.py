"""Min cost climbing stairs (tab-04), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-mincost.v1"

def min_cost(cost: list) -> int:
    if not cost: return 0
    a, b = 0, 0
    for c in cost:
        a, b = b, min(b, a) + c
    return min(a, b)

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True

def main() -> None:
    assert min_cost([10, 15, 20]) == 15
    assert min_cost([1, 100, 1, 1, 1, 100, 1, 1, 100, 1]) == 6
    assert min_cost([0]) == 0
    assert stdlib_only()
    print("tab-mincost OK")

if __name__ == "__main__": main()
