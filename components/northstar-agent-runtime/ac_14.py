"""GCD Util (D-AC-014), Simulated."""
from __future__ import annotations
import ast
import math
VERSION = "ac_14.v1"
def gcd(a: int, b: int) -> int:
    return math.gcd(a, b)
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
    assert gcd(12, 8) == 4
    assert gcd(7, 5) == 1
    assert gcd(0, 9) == 9
    assert stdlib_only()
    print("ac_14 OK")
if __name__ == "__main__": main()
