"""Dedupe Preserving Order."""
from __future__ import annotations
import ast

VERSION = "ah_03.v1"
def dedupe_ordered(xs: list) -> list:
    seen: set = set()
    return [x for x in xs if not (x in seen or seen.add(x))]
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
    assert dedupe_ordered([1, 2, 2, 3, 1]) == [1, 2, 3]
    assert dedupe_ordered([]) == []
    assert stdlib_only()
    print("ah_03 OK")
if __name__ == "__main__": main()
