"""Least common multiple (AB-07), Simulated."""
from __future__ import annotations
import ast
import math
VERSION = "lcm.v1"
def lcm(a: int, b: int) -> int:
    return a * b // math.gcd(a, b)
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "re", "math", "base64", "hashlib", "hmac", "urllib", "collections", "itertools", "string", "json", "bisect"}
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
    assert stdlib_only()
    print("lcm OK")
if __name__ == "__main__": main()
