"""Deep Merge, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_27.v1"
def dmerge(a: dict, b: dict) -> dict:
    out = dict(a)
    for k, v in b.items():
        out[k] = dmerge(out[k], v) if isinstance(out.get(k), dict) and isinstance(v, dict) else v
    return out
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
    assert dmerge({"a":1},{"b":2}) == {"a":1,"b":2}
    assert dmerge({"a":{"x":1}},{"a":{"y":2}}) == {"a":{"x":1,"y":2}}
    assert dmerge({"a":1},{"a":2}) == {"a":2}
    assert stdlib_only()
    print("ag_27 OK")
if __name__ == "__main__": main()
