"""Count Vowels Util (D-U-007), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_07.v1"
def count_vowels(s: str) -> int:
    return sum(1 for c in s.lower() if c in 'aeiou')
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
    assert count_vowels("hello") == 2
    assert count_vowels("xyz") == 0
    assert count_vowels("AEIOU") == 5
    assert stdlib_only()
    print("aa_07 OK")
if __name__ == "__main__": main()
