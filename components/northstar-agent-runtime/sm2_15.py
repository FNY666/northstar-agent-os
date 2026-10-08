"""Remove duplicate characters, keep order. (sm2-15)."""
from __future__ import annotations
import ast
VERSION = "sm2-dedup.v1"

def dedup_chars(s: str) -> str:
    seen = set()
    out = []
    for c in s:
        if c not in seen:
            seen.add(c); out.append(c)
    return ''.join(out)

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
    assert dedup_chars('aabbc') == 'abc'
    assert dedup_chars('') == ''
    assert dedup_chars('aaa') == 'a'
    assert stdlib_only()

if __name__ == "__main__":
    main()
