"""Mean Of List."""
from __future__ import annotations
import ast

VERSION = "ah_09.v1"
def mean_list(xs: list) -> float:
    return sum(xs) / len(xs) if xs else 0.0
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
    assert mean_list([1, 2, 3]) == 2.0
    assert mean_list([]) == 0.0
    assert mean_list([5]) == 5.0
    assert stdlib_only()
    print("ah_09 OK")
if __name__ == "__main__": main()
