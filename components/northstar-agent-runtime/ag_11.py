"""Backoff Schedule, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_11.v1"
def backoff_ms(attempt: int, base: int = 100, cap: int = 5000) -> int:
    if attempt < 0: raise ValueError("bad attempt")
    return min(cap, base * (2 ** attempt))
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
    assert backoff_ms(0) == 100
    assert backoff_ms(2) == 400
    assert backoff_ms(20) == 5000
    assert stdlib_only()
    print("ag_11 OK")
if __name__ == "__main__": main()
