"""Mod Pow Util (D-AC-046), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_46.v1"
def mod_pow(a: int, e: int, m: int) -> int:
    return pow(a, e, m)
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
    assert mod_pow(2, 10, 1000) == 24
    assert mod_pow(3, 0, 7) == 1
    assert mod_pow(5, 3, 13) == 8
    assert stdlib_only()
    print("ac_46 OK")
if __name__ == "__main__": main()
