"""Camel To Snake Case."""
from __future__ import annotations
import ast

VERSION = "ah_26.v1"
def to_snake(s: str) -> str:
    return ''.join('_' + c.lower() if c.isupper() else c for c in s).lstrip('_')
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
    assert to_snake('camelCase') == 'camel_case'
    assert to_snake('Already_snake') == 'already_snake'
    assert stdlib_only()
    print("ah_26 OK")
if __name__ == "__main__": main()
