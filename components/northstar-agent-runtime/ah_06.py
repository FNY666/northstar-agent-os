"""Basic Slugify."""
from __future__ import annotations
import ast

VERSION = "ah_06.v1"
def slugify_basic(s: str) -> str:
    return '-'.join(w for w in ''.join(c.lower() if c.isalnum() else ' ' for c in s).split())
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
    assert slugify_basic('Hello World!') == 'hello-world'
    assert slugify_basic('  A  B ') == 'a-b'
    assert stdlib_only()
    print("ah_06 OK")
if __name__ == "__main__": main()
