"""Triangular Util (D-AC-027), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_27.v1"
def tri(n: int) -> int:
    return n * (n + 1) // 2
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
    assert tri(5) == 15
    assert tri(0) == 0
    assert tri(10) == 55
    assert stdlib_only()
    print("ac_27 OK")
if __name__ == "__main__": main()
