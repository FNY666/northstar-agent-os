"""Deg2Rad Util (D-AC-040), Simulated."""
from __future__ import annotations
import ast
import math
VERSION = "ac_40.v1"
def deg2rad(d: float) -> float:
    return d * math.pi / 180.0
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
    assert abs(deg2rad(180) - math.pi) < 1e-9
    assert deg2rad(0) == 0.0
    assert abs(deg2rad(90) - math.pi / 2) < 1e-9
    assert stdlib_only()
    print("ac_40 OK")
if __name__ == "__main__": main()
