"""Reverse String."""
from __future__ import annotations
import ast

VERSION = "ah_05.v1"
def reverse_string(s: str) -> str:
    return s[::-1]
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
    assert reverse_string('abc') == 'cba'
    assert reverse_string('') == ''
    assert reverse_string('a') == 'a'
    assert stdlib_only()
    print("ah_05 OK")
if __name__ == "__main__": main()
