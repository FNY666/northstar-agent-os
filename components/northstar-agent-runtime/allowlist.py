"""Allowlist validation (D-IN-027), Simulated."""
from __future__ import annotations
import ast
VERSION = "allowlist-v1"
class Allowlist:
    def __init__(self, allowed: list):
        self.allowed = set(allowed)
    def check(self, value: str) -> bool:
        return value in self.allowed
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
    a = Allowlist(["read", "write"])
    assert a.check("read")
    assert not a.check("delete")
    assert stdlib_only()
    print("allowlist OK")
if __name__ == "__main__": main()
