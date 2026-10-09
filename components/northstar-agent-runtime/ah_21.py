"""Pad List To Length."""
from __future__ import annotations
import ast

VERSION = "ah_21.v1"
def pad_list(xs: list, n: int, fill=None) -> list:
    return list(xs) + [fill] * max(0, n - len(xs))
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
    assert pad_list([1, 2], 4, 0) == [1, 2, 0, 0]
    assert pad_list([1, 2, 3], 2) == [1, 2, 3]
    assert stdlib_only()
    print("ah_21 OK")
if __name__ == "__main__": main()
