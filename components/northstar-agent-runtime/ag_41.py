"""Isogram Check, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_41.v1"
def is_isogram(s: str) -> bool:
    t = [c.lower() for c in s if c.isalpha()]
    return len(set(t)) == len(t)
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
    assert is_isogram("subdermatoglyphic") is True
    assert is_isogram("hello") is False
    assert is_isogram("") is True
    assert stdlib_only()
    print("ag_41 OK")
if __name__ == "__main__": main()
