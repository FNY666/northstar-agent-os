"""Set Nested Dict Value."""
from __future__ import annotations
import ast

VERSION = "ah_34.v1"
def set_nested(d: dict, value, *keys) -> dict:
    node = d
    for k in keys[:-1]:
        node = node.setdefault(k, {})
    node[keys[-1]] = value
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
    assert set_nested({}, 1, 'a', 'b') == {'a': {'b': 1}}
    assert set_nested({'a': 1}, 2, 'a') == {'a': 2}
    assert stdlib_only()
    print("ah_34 OK")
if __name__ == "__main__": main()
