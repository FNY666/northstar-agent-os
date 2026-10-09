"""LCM Util (D-AC-015), Simulated."""
from __future__ import annotations
import ast
import math
VERSION = "ac_15.v1"
def lcm(a: int, b: int) -> int:
    return abs(a * b) // math.gcd(a, b) if a and b else 0
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
    assert lcm(4, 6) == 12
    assert lcm(7, 5) == 35
    assert lcm(0, 5) == 0
    assert stdlib_only()
    print("ac_15 OK")
if __name__ == "__main__": main()
