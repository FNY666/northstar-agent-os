"""Safe Token Compare, Simulated."""
from __future__ import annotations
import ast
import secrets
VERSION = "ag_06.v1"
def safe_eq(a: str, b: str) -> bool:
    return secrets.compare_digest(a.encode(), b.encode())
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
    assert safe_eq("abc", "abc") is True
    assert safe_eq("abc", "abd") is False
    assert safe_eq("", "") is True
    assert stdlib_only()
    print("ag_06 OK")
if __name__ == "__main__": main()
