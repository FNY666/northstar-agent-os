"""Truncate Util (D-U-009), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_09.v1"
def truncate(s: str, n: int, suffix: str = '...') -> str:
    return s if len(s) <= n else s[:n] + suffix
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
    assert truncate("abcdef", 3) == "abc..."
    assert truncate("ab", 3) == "ab"
    assert truncate("abc", 3) == "abc"
    assert stdlib_only()
    print("aa_09 OK")
if __name__ == "__main__": main()
