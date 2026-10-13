"""Punctuation normalization (D-IN-020), Simulated."""
from __future__ import annotations
import ast, re
VERSION = "punct-norm.v1"
def normalize(t: str) -> str:
    return re.sub(r"[^\w\s]", " ", t)
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
    assert " " in normalize("hello,world!")
    assert stdlib_only()
    print("punct-norm OK")
if __name__ == "__main__": main()
