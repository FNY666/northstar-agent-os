"""Hypot2 Util (D-AC-039), Simulated."""
from __future__ import annotations
import ast
import math
VERSION = "ac_39.v1"
def hypot2(x: float, y: float) -> float:
    return math.hypot(x, y)
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
    assert hypot2(3, 4) == 5.0
    assert hypot2(0, 0) == 0.0
    assert hypot2(5, 12) == 13.0
    assert stdlib_only()
    print("ac_39 OK")
if __name__ == "__main__": main()
