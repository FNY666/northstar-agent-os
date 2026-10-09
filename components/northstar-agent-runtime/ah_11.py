"""Mode Of List."""
from __future__ import annotations
import ast

VERSION = "ah_11.v1"
def mode_list(xs: list):
    from collections import Counter
    return Counter(xs).most_common(1)[0][0] if xs else None
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
    assert mode_list([1, 2, 2, 3]) == 2
    assert mode_list([]) is None
    assert stdlib_only()
    print("ah_11 OK")
if __name__ == "__main__": main()
