"""Palindrome Check, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_38.v1"
def is_pal(s: str) -> bool:
    t = "".join(c.lower() for c in s if c.isalnum())
    return t == t[::-1]
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
    assert is_pal("A man a plan a canal Panama") is True
    assert is_pal("hello") is False
    assert is_pal("") is True
    assert stdlib_only()
    print("ag_38 OK")
if __name__ == "__main__": main()
