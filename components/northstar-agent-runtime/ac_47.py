"""Divmod Pair Util (D-AC-047), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_47.v1"
def divmod_pair(a: int, b: int) -> tuple:
    return divmod(a, b)
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
    assert divmod_pair(7, 3) == (2, 1)
    assert divmod_pair(9, 3) == (3, 0)
    assert divmod_pair(0, 5) == (0, 0)
    assert stdlib_only()
    print("ac_47 OK")
if __name__ == "__main__": main()
