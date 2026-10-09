"""Counter Util (D-U-029), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_29.v1"
def counter(xs: list) -> dict:
    out: dict = {}
    for x in xs:
        out[x] = out.get(x, 0) + 1
    return out
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
    assert counter([1,1,2]) == {1:2,2:1}
    assert counter([]) == {}
    assert counter("aab") == {"a":2,"b":1}
    assert stdlib_only()
    print("aa_29 OK")
if __name__ == "__main__": main()
