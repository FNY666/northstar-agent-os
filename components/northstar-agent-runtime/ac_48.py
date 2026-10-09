"""Avg3 Util (D-AC-048), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_48.v1"
def avg3(a: float, b: float, c: float) -> float:
    return (a + b + c) / 3
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
    assert avg3(3, 6, 9) == 6.0
    assert avg3(0, 0, 0) == 0.0
    assert avg3(1, 2, 3) == 2.0
    assert stdlib_only()
    print("ac_48 OK")
if __name__ == "__main__": main()
