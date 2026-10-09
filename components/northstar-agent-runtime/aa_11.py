"""Gcd Util (D-U-011), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_11.v1"
def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)
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
    assert gcd(12, 8) == 4
    assert gcd(7, 5) == 1
    assert gcd(0, 5) == 5
    assert stdlib_only()
    print("aa_11 OK")
if __name__ == "__main__": main()
