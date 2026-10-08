"""Language detection filter mock (D-IN-003), Simulated."""
from __future__ import annotations
import ast
VERSION = "lang-filter.v1"
ALLOWED = {"en", "zh"}
def detect(text: str) -> str:
    if any("\u4e00" <= c <= "\u9fff" for c in text): return "zh"
    return "en"
def check(text: str) -> bool: return detect(text) in ALLOWED
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
    assert check("hello")
    assert check("你好")
    assert stdlib_only()
    print("lang-filter OK")
if __name__ == "__main__": main()
