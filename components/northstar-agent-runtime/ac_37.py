"""Clamp01 Util (D-AC-037), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_37.v1"
def clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))
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
    assert clamp01(0.5) == 0.5
    assert clamp01(2.0) == 1.0
    assert clamp01(-1.0) == 0.0
    assert stdlib_only()
    print("ac_37 OK")
if __name__ == "__main__": main()
