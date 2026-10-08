"""Convert to snake_case. (sm2-06)."""
from __future__ import annotations
import ast
VERSION = "sm2-snake.v1"

def to_snake(s: str) -> str:
    out = []
    for c in s.strip():
        if c.isupper():
            out.append('_' + c.lower())
        elif c in ' -':
            out.append('_')
        else:
            out.append(c)
    return ''.join(out).strip('_').replace('__', '_')

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
    assert to_snake('helloWorld') == 'hello_world'
    assert to_snake('Foo Bar') == 'foo_bar'
    assert to_snake('abc') == 'abc'
    assert stdlib_only()

if __name__ == "__main__":
    main()
