"""Dedupe Ordered, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_13.v1"
def dedupe(xs: list) -> list:
    seen, out = set(), []
    for x in xs:
        if x not in seen: seen.add(x); out.append(x)
    return out
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
    assert dedupe([1,2,1,3,2]) == [1,2,3]
    assert dedupe([]) == []
    assert dedupe(["a","a","b"]) == ["a","b"]
    assert stdlib_only()
    print("ag_13 OK")
if __name__ == "__main__": main()
