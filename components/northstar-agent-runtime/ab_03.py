"""Case-insensitive palindrome check (AB-03), Simulated."""
from __future__ import annotations
import ast

VERSION = "is-pal.v1"
def is_pal(s: str) -> bool:
    t = s.lower()
    return t == t[::-1]
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
    assert is_pal("Racecar")
    assert not is_pal("hello")
    assert is_pal("abba")
    assert stdlib_only()
    print("is-pal OK")
if __name__ == "__main__": main()
