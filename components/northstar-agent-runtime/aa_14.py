"""Factorial Util (D-U-014), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_14.v1"
def factorial(n: int) -> int:
    r = 1
    for i in range(2, n + 1):
        r *= i
    return r
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
    assert factorial(5) == 120
    assert factorial(0) == 1
    assert factorial(1) == 1
    assert stdlib_only()
    print("aa_14 OK")
if __name__ == "__main__": main()
