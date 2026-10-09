"""First N Characters."""
from __future__ import annotations
import ast

VERSION = "ah_23.v1"
def head_str(s: str, n: int) -> str:
    return s[:n]
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
    assert head_str('hello', 2) == 'he'
    assert head_str('hi', 9) == 'hi'
    assert stdlib_only()
    print("ah_23 OK")
if __name__ == "__main__": main()
