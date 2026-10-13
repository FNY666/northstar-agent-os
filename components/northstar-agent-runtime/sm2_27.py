"""Starts-with and ends-with pair check. (sm2-27)."""
from __future__ import annotations
import ast
VERSION = "sm2-affix.v1"

def has_affixes(s: str, pre: str, suf: str) -> bool:
    return s.startswith(pre) and s.endswith(suf)

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
    assert has_affixes('unhappiness', 'un', 'ness')
    assert not has_affixes('happy', 'un', 'ness')
    assert has_affixes('', '', '')
    assert stdlib_only()

if __name__ == "__main__":
    main()
