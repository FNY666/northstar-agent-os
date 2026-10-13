"""Convert to kebab-case. (sm2-07)."""
from __future__ import annotations
import ast
VERSION = "sm2-kebab.v1"

def to_kebab(s: str) -> str:
    return s.replace('_', '-').replace(' ', '-').lower()

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
    assert to_kebab('hello_world') == 'hello-world'
    assert to_kebab('Foo Bar') == 'foo-bar'
    assert to_kebab('abc') == 'abc'
    assert stdlib_only()

if __name__ == "__main__":
    main()
