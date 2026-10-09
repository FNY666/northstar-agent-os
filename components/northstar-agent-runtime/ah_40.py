"""List Intersection."""
from __future__ import annotations
import ast

VERSION = "ah_40.v1"
def list_intersect(a: list, b: list) -> list:
    s = set(b)
    return [x for x in a if x in s]
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
    assert list_intersect([1, 2, 3], [2, 4]) == [2]
    assert list_intersect([], [1]) == []
    assert stdlib_only()
    print("ah_40 OK")
if __name__ == "__main__": main()
