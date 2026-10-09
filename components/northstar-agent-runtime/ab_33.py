"""Anagram check (AB-33), Simulated."""
from __future__ import annotations
import ast

VERSION = "anagram.v1"
def is_anagram(a: str, b: str) -> bool:
    return sorted(a) == sorted(b)
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
    assert is_anagram("abc", "cba")
    assert not is_anagram("ab", "cd")
    assert stdlib_only()
    print("anagram OK")
if __name__ == "__main__": main()
