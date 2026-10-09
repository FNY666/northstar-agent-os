"""Halve Util (D-AC-012), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_12.v1"
def halve(n: float) -> float:
    return n / 2
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
    assert halve(8) == 4.0
    assert halve(5) == 2.5
    assert halve(0) == 0.0
    assert stdlib_only()
    print("ac_12 OK")
if __name__ == "__main__": main()
