"""Output length guard (D-OUT-007b), Simulated."""
from __future__ import annotations
import ast
VERSION = "out-len-guard.v1"
def check(t: str, m: int = 5000) -> bool: return len(t) <= m
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
    assert check("hi")
    assert not check("x"*6000)
    assert stdlib_only()
    print("out-len-guard OK")
if __name__ == "__main__": main()
