"""Median Util (D-U-017), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_17.v1"
def median(xs: list) -> float:
    s = sorted(xs)
    n = len(s)
    return (s[n//2] + s[(n-1)//2]) / 2 if n else 0.0
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
    assert median([1,3,2]) == 2.0
    assert median([1,2,3,4]) == 2.5
    assert median([]) == 0.0
    assert stdlib_only()
    print("aa_17 OK")
if __name__ == "__main__": main()
