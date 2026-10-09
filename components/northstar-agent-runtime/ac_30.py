"""N Choose R Util (D-AC-030), Simulated."""
from __future__ import annotations
import ast
import math
VERSION = "ac_30.v1"
def ncr(n: int, r: int) -> int:
    return math.comb(n, r)
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "math", "pathlib", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert ncr(5, 2) == 10
    assert ncr(5, 0) == 1
    assert ncr(4, 4) == 1
    assert stdlib_only()
    print("ac_30 OK")
if __name__ == "__main__": main()
