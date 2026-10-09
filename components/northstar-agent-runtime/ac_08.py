"""Min3 Util (D-AC-008), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_08.v1"
def min3(a: float, b: float, c: float) -> float:
    return min(a, b, c)
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
    assert min3(3, 1, 2) == 1
    assert min3(5, 5, 5) == 5
    assert min3(-1, 0, 1) == -1
    assert stdlib_only()
    print("ac_08 OK")
if __name__ == "__main__": main()
