"""Reverse Words Util (D-U-006), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_06.v1"
def reverse_words(s: str) -> str:
    return ' '.join(reversed(s.split()))
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
    assert reverse_words("a b c") == "c b a"
    assert reverse_words("") == ""
    assert reverse_words("x") == "x"
    assert stdlib_only()
    print("aa_06 OK")
if __name__ == "__main__": main()
