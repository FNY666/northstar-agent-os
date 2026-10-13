"""Homoglyph normalization (D-IN-011), Simulated."""
from __future__ import annotations
import ast
VERSION = "homoglyph-norm.v1"
MAP = {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x"}
def normalize(t: str) -> str:
    for k, v in MAP.items(): t = t.replace(k, v)
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
    assert normalize("аpple") == "apple"
    assert stdlib_only()
    print("homoglyph-norm OK")
if __name__ == "__main__": main()
