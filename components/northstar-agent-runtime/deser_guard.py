"""Deserialization guard (D-OUT-029), Simulated."""
from __future__ import annotations
import ast, re
VERSION = "deser-guard.v1"
DANGEROUS = [r"pickle\.loads", r"yaml\.load\s*\(", r"marshal\.loads"]
def detect(code: str) -> list:
    return [p for p in DANGEROUS if re.search(p, code)]
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
    assert len(detect("pickle.loads(data)")) > 0
    assert stdlib_only()
    print("deser-guard OK")
if __name__ == "__main__": main()
