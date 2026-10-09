"""Capitalize each word (AB-27), Simulated."""
from __future__ import annotations
import ast

VERSION = "titlew.v1"
def title_words(s: str) -> str:
    return " ".join(w.capitalize() for w in s.split())
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
    assert title_words("a b") == "A B"
    assert title_words("x") == "X"
    assert stdlib_only()
    print("titlew OK")
if __name__ == "__main__": main()
