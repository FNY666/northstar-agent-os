"""Rad2Deg Util (D-AC-041), Simulated."""
from __future__ import annotations
import ast
import math
VERSION = "ac_41.v1"
def rad2deg(r: float) -> float:
    return r * 180.0 / math.pi
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
    assert rad2deg(math.pi) == 180.0
    assert rad2deg(0.0) == 0.0
    assert abs(rad2deg(math.pi / 2) - 90.0) < 1e-9
    assert stdlib_only()
    print("ac_41 OK")
if __name__ == "__main__": main()
