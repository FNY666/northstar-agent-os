"""Flatten one level (AB-11), Simulated."""
from __future__ import annotations
import ast

VERSION = "flatten.v1"
def flatten(lists: list) -> list:
    return [x for sub in lists for x in sub]
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
    assert flatten([[1, 2], [3]]) == [1, 2, 3]
    assert flatten([]) == []
    assert stdlib_only()
    print("flatten OK")
if __name__ == "__main__": main()
