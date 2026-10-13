"""Whitespace normalization (D-IN-018), Simulated."""
from __future__ import annotations
import ast, re
VERSION = "ws-norm.v1"
def normalize(t: str) -> str: return re.sub(r"\s+", " ", t).strip()
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
    assert normalize("a  b\tc") == "a b c"
    assert stdlib_only()
    print("ws-norm OK")
if __name__ == "__main__": main()
