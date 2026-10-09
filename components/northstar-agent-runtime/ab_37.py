"""Merge dicts (b wins) (AB-37), Simulated."""
from __future__ import annotations
import ast

VERSION = "merged.v1"
def merge_dicts(a: dict, b: dict) -> dict:
    return {**a, **b}
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
    assert merge_dicts({'a': 1}, {'a': 2}) == {'a': 2}
    assert merge_dicts({}, {'x': 1}) == {'x': 1}
    assert stdlib_only()
    print("merged OK")
if __name__ == "__main__": main()
