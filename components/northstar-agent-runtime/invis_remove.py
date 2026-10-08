"""Invisible char removal (D-IN-015), Simulated."""
from __future__ import annotations
import ast
VERSION = "invis-remove.v1"
INVIS = ["\u200b", "\u200c", "\u200d", "\ufeff", "\u00ad"]
def clean(t: str) -> str:
    for c in INVIS: t = t.replace(c, "")
    return t
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
    assert clean("a\u200bb") == "ab"
    assert stdlib_only()
    print("invis-remove OK")
if __name__ == "__main__": main()
