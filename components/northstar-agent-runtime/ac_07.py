"""Midpoint Util (D-AC-007), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_07.v1"
def midpoint(a: float, b: float) -> float:
    return (a + b) / 2
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
    assert midpoint(2, 8) == 5.0
    assert midpoint(0, 10) == 5.0
    assert midpoint(-4, 4) == 0.0
    assert stdlib_only()
    print("ac_07 OK")
if __name__ == "__main__": main()
