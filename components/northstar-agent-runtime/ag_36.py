"""Word Count, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_36.v1"
def wordcount(text: str) -> dict:
    out: dict = {}
    for w in text.split(): out[w] = out.get(w, 0) + 1
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
    assert wordcount("a b a") == {"a":2,"b":1}
    assert wordcount("") == {}
    assert wordcount("x") == {"x":1}
    assert stdlib_only()
    print("ag_36 OK")
if __name__ == "__main__": main()
