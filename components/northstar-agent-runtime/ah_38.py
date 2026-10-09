"""Omit Keys From Dict."""
from __future__ import annotations
import ast

VERSION = "ah_38.v1"
def omit_keys(d: dict, keys: list) -> dict:
    return {k: v for k, v in d.items() if k not in keys}
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
    assert omit_keys({'a': 1, 'b': 2}, ['a']) == {'b': 2}
    assert omit_keys({}, ['a']) == {}
    assert stdlib_only()
    print("ah_38 OK")
if __name__ == "__main__": main()
