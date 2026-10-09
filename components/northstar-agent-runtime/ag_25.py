"""Flatten Nested, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_25.v1"
def flatten(xs: list) -> list:
    out = []
    for x in xs:
        out += flatten(x) if isinstance(x, list) else [x]
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
    assert flatten([1,[2,[3]],4]) == [1,2,3,4]
    assert flatten([]) == []
    assert flatten([[[]]]) == []
    assert stdlib_only()
    print("ag_25 OK")
if __name__ == "__main__": main()
