"""Lerp Util (D-AC-038), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_38.v1"
def lerp(a: float, b: float, q: float) -> float:
    return a + (b - a) * q
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
    assert lerp(0, 10, 0.5) == 5.0
    assert lerp(0, 10, 0.0) == 0.0
    assert lerp(0, 10, 1.0) == 10.0
    assert stdlib_only()
    print("ac_38 OK")
if __name__ == "__main__": main()
