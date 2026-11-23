"""Bidi control removal (D-IN-016), Simulated."""
from __future__ import annotations
import ast
VERSION = "bidi-remove.v1"
BIDI = ["\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"]
def clean(t: str) -> str:
    for b in BIDI: t = t.replace(b, "")
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
    assert clean("a\u202eb") == "ab"
    assert stdlib_only()
    print("bidi-remove OK")
if __name__ == "__main__": main()
