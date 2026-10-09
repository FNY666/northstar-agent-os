"""Pick Keys From Dict."""
from __future__ import annotations
import ast

VERSION = "ah_37.v1"
def pick_keys(d: dict, keys: list) -> dict:
    return {k: d[k] for k in keys if k in d}
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
    assert pick_keys({'a': 1, 'b': 2}, ['a']) == {'a': 1}
    assert pick_keys({'a': 1}, ['z']) == {}
    assert stdlib_only()
    print("ah_37 OK")
if __name__ == "__main__": main()
