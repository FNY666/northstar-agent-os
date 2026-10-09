"""Flatten One Level."""
from __future__ import annotations
import ast

VERSION = "ah_04.v1"
def flatten_one(nested: list) -> list:
    return [x for sub in nested for x in sub]
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
    assert flatten_one([[1, 2], [3], []]) == [1, 2, 3]
    assert flatten_one([]) == []
    assert stdlib_only()
    print("ah_04 OK")
if __name__ == "__main__": main()
