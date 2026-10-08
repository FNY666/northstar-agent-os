"""Zero-width removal (D-IN-017), Simulated."""
from __future__ import annotations
import ast, re
VERSION = "zw-remove.v1"
ZW = ["\u200b", "\u200c", "\u200d", "\ufeff"]
def clean(t: str) -> str:
    for z in ZW: t = t.replace(z, "")
    return t
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "re", "typing"}
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
    print("zw-remove OK")
if __name__ == "__main__": main()
