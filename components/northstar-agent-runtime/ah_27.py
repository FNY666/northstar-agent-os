"""Snake To Camel Case."""
from __future__ import annotations
import ast

VERSION = "ah_27.v1"
def to_camel(s: str) -> str:
    parts = s.split('_')
    return parts[0] + ''.join(p.capitalize() for p in parts[1:])
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
    assert to_camel('snake_case') == 'snakeCase'
    assert to_camel('x') == 'x'
    assert stdlib_only()
    print("ah_27 OK")
if __name__ == "__main__": main()
