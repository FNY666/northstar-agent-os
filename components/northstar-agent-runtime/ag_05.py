"""GCD LCM, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_05.v1"
def gcd(a: int, b: int) -> int:
    while b: a, b = b, a % b
    return abs(a)
def lcm(a: int, b: int) -> int:
    return abs(a * b) // gcd(a, b)
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "base64", "collections", "hashlib", "hmac", "itertools", "math", "pathlib", "secrets", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert gcd(12, 18) == 6
    assert lcm(4, 6) == 12
    assert gcd(7, 5) == 1
    assert stdlib_only()
    print("ag_05 OK")
if __name__ == "__main__": main()
