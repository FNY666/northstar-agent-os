"""Get Nested Dict Value."""
from __future__ import annotations
import ast

VERSION = "ah_33.v1"
def get_nested(d: dict, *keys, default=None):
    for k in keys:
        if not isinstance(d, dict): return default
        d = d.get(k, default)
    return d
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
    assert get_nested({'a': {'b': 1}}, 'a', 'b') == 1
    assert get_nested({}, 'a', 'b', default='x') == 'x'
    assert stdlib_only()
    print("ah_33 OK")
if __name__ == "__main__": main()
