"""Top N By Key."""
from __future__ import annotations
import ast

VERSION = "ah_45.v1"
def top_n_by(xs: list, n: int, key) -> list:
    return sorted(xs, key=key, reverse=True)[:n]
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
    assert top_n_by([3, 1, 2], 2, lambda x: x) == [3, 2]
    assert top_n_by([], 3, str) == []
    assert stdlib_only()
    print("ah_45 OK")
if __name__ == "__main__": main()
