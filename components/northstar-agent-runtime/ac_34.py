"""Sum Cubes Util (D-AC-034), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_34.v1"
def sum_cube(n: int) -> int:
    q = n * (n + 1) // 2
    return q * q
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
    assert sum_cube(3) == 36
    assert sum_cube(0) == 0
    assert sum_cube(2) == 9
    assert stdlib_only()
    print("ac_34 OK")
if __name__ == "__main__": main()
