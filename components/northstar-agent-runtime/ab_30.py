"""Strip punctuation (AB-30), Simulated."""
from __future__ import annotations
import ast

VERSION = "nopunct.v1"
def strip_punct(s: str) -> str:
    return ''.join(c for c in s if c.isalnum() or c.isspace())
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
    assert strip_punct("a,b!") == "ab"
    assert strip_punct("x y") == "x y"
    assert stdlib_only()
    print("nopunct OK")
if __name__ == "__main__": main()
