"""Lcm Util (D-U-012), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_12.v1"
def lcm(a: int, b: int) -> int:
    from math import gcd as _g
    return abs(a * b) // _g(a, b) if a and b else 0
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "base64", "collections", "hashlib", "hmac", "math", "pathlib", "secrets", "typing"}
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
    print("aa_12 OK")
if __name__ == "__main__": main()
