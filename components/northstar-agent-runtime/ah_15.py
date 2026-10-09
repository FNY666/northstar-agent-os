"""Word Count."""
from __future__ import annotations
import ast

VERSION = "ah_15.v1"
def count_words(s: str) -> int:
    return len(s.split())
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
    assert count_words('hello world') == 2
    assert count_words('   ') == 0
    assert count_words('') == 0
    assert stdlib_only()
    print("ah_15 OK")
if __name__ == "__main__": main()
