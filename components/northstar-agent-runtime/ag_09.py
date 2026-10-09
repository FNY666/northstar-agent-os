"""Token Bucket, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_09.v1"
def bucket_ok(tokens: float, cost: float, cap: float) -> float:
    if tokens < cost: raise ValueError("insufficient")
    return min(cap, tokens - cost)
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
    assert bucket_ok(10.0, 3.0, 10.0) == 7.0
    assert bucket_ok(1.0, 1.0, 5.0) == 0.0
    try:
        bucket_ok(0.5, 1.0, 5.0); assert False
    except ValueError: pass
    assert stdlib_only()
    print("ag_09 OK")
if __name__ == "__main__": main()
