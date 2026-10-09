"""Filter Keys Util (D-U-028), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_28.v1"
def filter_keys(d: dict, keys: list) -> dict:
    return {k: v for k, v in d.items() if k in keys}
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "base64", "collections", "hashlib", "hmac", "math", "pathlib", "secrets", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert filter_keys({"a":1,"b":2}, ["a"]) == {"a":1}
    assert filter_keys({}, []) == {}
    assert filter_keys({"a":1}, ["z"]) == {}
    assert stdlib_only()
    print("aa_28 OK")
if __name__ == "__main__": main()
