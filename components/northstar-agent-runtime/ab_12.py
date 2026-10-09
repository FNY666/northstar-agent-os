"""Dedupe preserving order (AB-12), Simulated."""
from __future__ import annotations
import ast

VERSION = "dedupe.v1"
def dedupe(seq: list) -> list:
    return list(dict.fromkeys(seq))
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
    assert dedupe([1, 2, 1, 3]) == [1, 2, 3]
    assert dedupe([]) == []
    assert stdlib_only()
    print("dedupe OK")
if __name__ == "__main__": main()
