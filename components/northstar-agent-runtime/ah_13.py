"""LCM Of Pair."""
from __future__ import annotations
import ast

VERSION = "ah_13.v1"
def lcm_pair(a: int, b: int) -> int:
    import math
    return abs(a * b) // math.gcd(a, b) if a and b else 0
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
    assert lcm_pair(4, 6) == 12
    assert lcm_pair(0, 5) == 0
    assert stdlib_only()
    print("ah_13 OK")
if __name__ == "__main__": main()
