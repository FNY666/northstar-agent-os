"""Levenshtein Distance, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_16.v1"
def lev(a: str, b: str) -> int:
    r = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        p, r[0] = r[0], i
        for j, cb in enumerate(b, 1): p, r[j] = r[j], min(r[j]+1, r[j-1]+1, p+(ca != cb))
    return r[-1]
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
    assert lev("kitten", "sitting") == 3
    assert lev("", "abc") == 3
    assert lev("same", "same") == 0
    assert stdlib_only()
    print("ag_16 OK")
if __name__ == "__main__": main()
