"""Prime Check, Simulated."""
from __future__ import annotations
import ast
import math
VERSION = "ag_43.v1"
def is_prime(n: int) -> bool:
    if n < 2: return False
    if n % 2 == 0: return n == 2
    return all(n % i for i in range(3, int(math.sqrt(n)) + 1, 2))
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
    assert is_prime(13) is True
    assert is_prime(1) is False
    assert is_prime(100) is False
    assert stdlib_only()
    print("ag_43 OK")
if __name__ == "__main__": main()
