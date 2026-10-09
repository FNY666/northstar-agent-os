"""Nested dict get (AB-39), Simulated."""
from __future__ import annotations
import ast

VERSION = "deepget.v1"
def deep_get(d: dict, keys: list, default=None):
    for k in keys:
        d = d.get(k, {}) if isinstance(d, dict) else {}
    return d if d != {} else default
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "re", "math", "base64", "hashlib", "hmac", "urllib", "collections", "itertools", "string", "json", "bisect"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert deep_get({'a': {'b': 1}}, ['a', 'b']) == 1
    assert deep_get({}, ['x']) is None
    assert stdlib_only()
    print("deepget OK")
if __name__ == "__main__": main()
