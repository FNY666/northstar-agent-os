"""Caesar Cipher, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_40.v1"
def caesar(s: str, shift: int) -> str:
    def sh(c: str) -> str:
        if not c.isalpha(): return c
        b = ord("A") if c.isupper() else ord("a")
        return chr(b + (ord(c) - b + shift) % 26)
    return "".join(sh(c) for c in s)
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
    assert caesar("abc", 1) == "bcd"
    assert caesar("bcd", -1) == "abc"
    assert caesar("Hi!", 13) == "Uv!"
    assert stdlib_only()
    print("ag_40 OK")
if __name__ == "__main__": main()
