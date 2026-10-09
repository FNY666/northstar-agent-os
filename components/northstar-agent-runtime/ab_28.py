"""Truncate with ellipsis (AB-28), Simulated."""
from __future__ import annotations
import ast

VERSION = "trunc.v1"
def truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n - 3] + "..."
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
    assert truncate("hello", 5) == "hello"
    assert truncate("hello world", 8) == "hello..."
    assert stdlib_only()
    print("trunc OK")
if __name__ == "__main__": main()
