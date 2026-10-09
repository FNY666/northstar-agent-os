"""Shingle Set, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_35.v1"
def shingles(text: str, n: int) -> set:
    if n <= 0: raise ValueError("n>0")
    return {text[i:i+n] for i in range(len(text) - n + 1)}
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
    assert shingles("abcd", 2) == {"ab","bc","cd"}
    assert shingles("aaa", 1) == {"a"}
    assert shingles("ab", 5) == set()
    assert stdlib_only()
    print("ag_35 OK")
if __name__ == "__main__": main()
