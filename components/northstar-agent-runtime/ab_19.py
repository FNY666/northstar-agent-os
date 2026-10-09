"""Caesar shift (AB-19), Simulated."""
from __future__ import annotations
import ast

VERSION = "caesar.v1"
def caesar(s: str, k: int) -> str:
    return ''.join(chr((ord(c) - 97 + k) % 26 + 97) if 'a' <= c <= 'z' else c for c in s)
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
    assert caesar("abc", 1) == "bcd"
    assert caesar("xyz", 2) == "zab"
    assert stdlib_only()
    print("caesar OK")
if __name__ == "__main__": main()
