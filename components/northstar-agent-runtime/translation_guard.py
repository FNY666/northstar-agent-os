"""Translation guard mock (D-OUT-021), Simulated."""
from __future__ import annotations
import ast
VERSION = "translation-guard.v1"
def check(text: str, target_lang: str) -> bool:
    return len(text) < 5000
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
    assert check("hello", "es")
    assert stdlib_only()
    print("translation-guard OK")
if __name__ == "__main__": main()
