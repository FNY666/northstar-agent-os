"""N Perm R Util (D-AC-031), Simulated."""
from __future__ import annotations
import ast
import math
VERSION = "ac_31.v1"
def npr(n: int, r: int) -> int:
    return math.perm(n, r)
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
    assert npr(5, 2) == 20
    assert npr(5, 0) == 1
    assert npr(4, 4) == 24
    assert stdlib_only()
    print("ac_31 OK")
if __name__ == "__main__": main()
