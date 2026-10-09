"""Sum Squares Util (D-AC-033), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_33.v1"
def sum_sq(n: int) -> int:
    return n * (n + 1) * (2 * n + 1) // 6
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
    assert sum_sq(3) == 14
    assert sum_sq(0) == 0
    assert sum_sq(5) == 55
    assert stdlib_only()
    print("ac_33 OK")
if __name__ == "__main__": main()
