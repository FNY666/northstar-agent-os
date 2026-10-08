"""Convert to camelCase. (sm2-05)."""
from __future__ import annotations
import ast
VERSION = "sm2-camel.v1"

def to_camel(s: str) -> str:
    parts = s.replace('-', ' ').replace('_', ' ').split()
    return parts[0].lower() + ''.join(p.capitalize() for p in parts[1:]) if parts else ''

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True

def main() -> None:
    assert to_camel('hello_world') == 'helloWorld'
    assert to_camel('foo-bar-baz') == 'fooBarBaz'
    assert to_camel('') == ''
    assert stdlib_only()

if __name__ == "__main__":
    main()
