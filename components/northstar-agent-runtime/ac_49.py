"""Geo Mean2 Util (D-AC-049), Simulated."""
from __future__ import annotations
import ast
import math
VERSION = "ac_49.v1"
def geo_mean2(a: float, b: float) -> float:
    return math.sqrt(a * b)
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
    assert geo_mean2(4, 9) == 6.0
    assert geo_mean2(1, 1) == 1.0
    assert geo_mean2(2, 8) == 4.0
    assert stdlib_only()
    print("ac_49 OK")
if __name__ == "__main__": main()
