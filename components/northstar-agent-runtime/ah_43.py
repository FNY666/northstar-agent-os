"""Adjacent Pairs."""
from __future__ import annotations
import ast

VERSION = "ah_43.v1"
def pairwise_list(xs: list) -> list:
    import itertools
    return list(itertools.pairwise(xs))
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
    assert pairwise_list([1, 2, 3]) == [(1, 2), (2, 3)]
    assert pairwise_list([1]) == []
    assert stdlib_only()
    print("ah_43 OK")
if __name__ == "__main__": main()
