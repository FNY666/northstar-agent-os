"""Ceil Div Util (D-AC-026), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_26.v1"
def ceil_div(a: int, b: int) -> int:
    return -(-a // b)
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
    assert ceil_div(7, 2) == 4
    assert ceil_div(8, 2) == 4
    assert ceil_div(0, 5) == 0
    assert stdlib_only()
    print("ac_26 OK")
if __name__ == "__main__": main()
