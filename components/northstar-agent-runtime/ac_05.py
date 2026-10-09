"""Abs Diff Util (D-AC-005), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_05.v1"
def abs_diff(a: float, b: float) -> float:
    return abs(a - b)
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
    assert abs_diff(5, 3) == 2
    assert abs_diff(3, 5) == 2
    assert abs_diff(4, 4) == 0
    assert stdlib_only()
    print("ac_05 OK")
if __name__ == "__main__": main()
