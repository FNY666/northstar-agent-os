"""Lowbit Util (D-AC-044), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_44.v1"
def lowbit(n: int) -> int:
    return n & -n
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
    assert lowbit(12) == 4
    assert lowbit(8) == 8
    assert lowbit(7) == 1
    assert stdlib_only()
    print("ac_44 OK")
if __name__ == "__main__": main()
