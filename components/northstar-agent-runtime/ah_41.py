"""Take Last N Items."""
from __future__ import annotations
import ast

VERSION = "ah_41.v1"
def take_last(xs: list, n: int) -> list:
    return xs[max(0, len(xs) - n):]
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
    assert take_last([1, 2, 3], 2) == [2, 3]
    assert take_last([1], 5) == [1]
    assert take_last([], 2) == []
    assert stdlib_only()
    print("ah_41 OK")
if __name__ == "__main__": main()
