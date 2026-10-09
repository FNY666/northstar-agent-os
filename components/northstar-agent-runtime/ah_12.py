"""GCD Of Pair."""
from __future__ import annotations
import ast

VERSION = "ah_12.v1"
def gcd_pair(a: int, b: int) -> int:
    import math
    return math.gcd(a, b)
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
    assert gcd_pair(12, 18) == 6
    assert gcd_pair(7, 13) == 1
    assert stdlib_only()
    print("ah_12 OK")
if __name__ == "__main__": main()
