"""Confusable detection (D-IN-012), Simulated."""
from __future__ import annotations
import ast
VERSION = "confusable-detect.v1"
def has_mixed_scripts(t: str) -> bool:
    latin = any("a" <= c <= "z" or "A" <= c <= "Z" for c in t)
    cyrillic = any("\u0400" <= c <= "\u04ff" for c in t)
    return latin and cyrillic
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
    assert has_mixed_scripts("aа")
    assert not has_mixed_scripts("abc")
    assert stdlib_only()
    print("confusable-detect OK")
if __name__ == "__main__": main()
