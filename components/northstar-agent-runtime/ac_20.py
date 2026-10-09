"""Reverse Num Util (D-AC-020), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_20.v1"
def reverse_num(n: int) -> int:
    r = int(str(abs(n))[::-1])
    return -r if n < 0 else r
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
    assert reverse_num(123) == 321
    assert reverse_num(-45) == -54
    assert reverse_num(100) == 1
    assert stdlib_only()
    print("ac_20 OK")
if __name__ == "__main__": main()
