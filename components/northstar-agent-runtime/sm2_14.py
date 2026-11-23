"""Character frequency map. (sm2-14)."""
from __future__ import annotations
import ast
VERSION = "sm2-freq.v1"

def char_freq(s: str) -> dict:
    d = {}
    for c in s:
        d[c] = d.get(c, 0) + 1
    return d

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
    assert char_freq('aab') == {'a': 2, 'b': 1}
    assert char_freq('') == {}
    assert char_freq('zz') == {'z': 2}
    assert stdlib_only()

if __name__ == "__main__":
    main()
