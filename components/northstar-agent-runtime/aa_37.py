"""Normalize Util (D-U-037), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_37.v1"
def normalize(xs: list) -> list:
    lo, hi = (min(xs), max(xs)) if xs else (0, 1)
    return [(x - lo) / (hi - lo) for x in xs] if hi > lo else [0.0] * len(xs)
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
    assert normalize([0,5,10]) == [0.0,0.5,1.0]
    assert normalize([]) == []
    assert normalize([3,3]) == [0.0,0.0]
    assert stdlib_only()
    print("aa_37 OK")
if __name__ == "__main__": main()
