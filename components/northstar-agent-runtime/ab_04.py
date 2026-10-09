"""Reverse word order (AB-04), Simulated."""
from __future__ import annotations
import ast

VERSION = "rev-words.v1"
def rev_words(s: str) -> str:
    return " ".join(s.split()[::-1])
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
    assert rev_words("a b c") == "c b a"
    assert rev_words("x") == "x"
    assert stdlib_only()
    print("rev-words OK")
if __name__ == "__main__": main()
