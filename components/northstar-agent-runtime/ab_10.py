"""Fibonacci (iterative) (AB-10), Simulated."""
from __future__ import annotations
import ast

VERSION = "fib.v1"
def fib(n: int) -> int:
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a
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
    assert fib(10) == 55
    assert fib(0) == 0
    assert fib(1) == 1
    assert stdlib_only()
    print("fib OK")
if __name__ == "__main__": main()
