"""Invert dict (AB-38), Simulated."""
from __future__ import annotations
import ast

VERSION = "invert.v1"
def invert(d: dict) -> dict:
    return {v: k for k, v in d.items()}
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
    assert invert({'a': 1}) == {1: 'a'}
    assert invert({}) == {}
    assert stdlib_only()
    print("invert OK")
if __name__ == "__main__": main()
