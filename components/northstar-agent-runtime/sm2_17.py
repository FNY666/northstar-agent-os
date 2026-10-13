"""Run-length encode. (sm2-17)."""
from __future__ import annotations
import ast
VERSION = "sm2-rle.v1"

def rle_encode(s: str) -> str:
    if not s: return ''
    out, cur, n = [], s[0], 1
    for c in s[1:]:
        n, cur = (n + 1, cur) if c == cur else (out.append(f'{cur}{n}') or 1, c)
    out.append(f'{cur}{n}')
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
    assert rle_encode('aaab') == 'a3b1'
    assert rle_encode('') == ''
    assert rle_encode('abc') == 'a1b1c1'
    assert stdlib_only()

if __name__ == "__main__":
    main()
