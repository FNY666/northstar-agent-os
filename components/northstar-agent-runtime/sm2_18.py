"""Run-length decode. (sm2-18)."""
from __future__ import annotations
import ast
VERSION = "sm2-rledec.v1"

def rle_decode(s: str) -> str:
    out, i = [], 0
    while i < len(s):
        j = i + 1
        while j < len(s) and s[j].isdigit(): j += 1
        out.append(s[i] * int(s[i + 1:j]))
        i = j
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
    assert rle_decode('a3b1') == 'aaab'
    assert rle_decode('') == ''
    assert rle_decode('a1b1c1') == 'abc'
    assert stdlib_only()

if __name__ == "__main__":
    main()
