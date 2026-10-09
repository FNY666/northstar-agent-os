"""Is Palindrome Util (D-U-005), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_05.v1"
def is_palindrome(s: str) -> bool:
    t = ''.join(c.lower() for c in s if c.isalnum())
    return t == t[::-1]
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
    assert is_palindrome("Racecar")
    assert not is_palindrome("hello")
    assert is_palindrome("A man, a plan, a canal: Panama")
    assert stdlib_only()
    print("aa_05 OK")
if __name__ == "__main__": main()
