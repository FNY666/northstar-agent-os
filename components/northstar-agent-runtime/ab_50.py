"""Levenshtein distance (AB-50), Simulated."""
from __future__ import annotations
import ast

VERSION = "lev.v1"
def lev(a: str, b: str) -> int:
    p = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        q = [i]
        for j, cb in enumerate(b, 1): q.append(min(p[j] + 1, q[-1] + 1, p[j - 1] + (ca != cb)))
        p = q
    return p[-1]
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
    assert lev("kitten", "sitting") == 3
    assert lev("", "") == 0
    assert stdlib_only()
    print("lev OK")
if __name__ == "__main__": main()
