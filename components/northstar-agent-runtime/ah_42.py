"""Running Total."""
from __future__ import annotations
import ast

VERSION = "ah_42.v1"
def running_total(xs: list) -> list:
    import itertools
    return list(itertools.accumulate(xs))
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
    assert running_total([1, 2, 3]) == [1, 3, 6]
    assert running_total([]) == []
    assert stdlib_only()
    print("ah_42 OK")
if __name__ == "__main__": main()
