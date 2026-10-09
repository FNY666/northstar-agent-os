"""Zip With None Padding."""
from __future__ import annotations
import ast

VERSION = "ah_50.v1"
def zip_pad(a: list, b: list) -> list:
    import itertools
    return list(itertools.zip_longest(a, b))
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
    assert zip_pad([1, 2], ['a']) == [(1, 'a'), (2, None)]
    assert zip_pad([], []) == []
    assert stdlib_only()
    print("ah_50 OK")
if __name__ == "__main__": main()
