"""Bytes To Human Size."""
from __future__ import annotations
import ast

VERSION = "ah_48.v1"
def human_size(n: int) -> str:
    import math
    u = ['B', 'KB', 'MB', 'GB', 'TB']
    i = min(int(math.log(n, 1024)) if n > 0 else 0, 4)
    return f'{n / 1024 ** i:.1f}{u[i]}'
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
    assert human_size(0) == '0.0B'
    assert human_size(1024) == '1.0KB'
    assert human_size(1536) == '1.5KB'
    assert stdlib_only()
    print("ah_48 OK")
if __name__ == "__main__": main()
