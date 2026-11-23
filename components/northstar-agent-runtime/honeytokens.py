"""Honeytokens: deception tokens (D-OUT-006), Simulated."""
from __future__ import annotations
import ast, secrets
from typing import Set
VERSION = "honeytokens.v1"
class HoneytokenManager:
    def __init__(self):
        self._tokens: Set[str] = set()
    def create(self, prefix: str = "AKIA") -> str:
        t = prefix + secrets.token_hex(10).upper()
        self._tokens.add(t)
        return t
    def is_honeytoken(self, s: str) -> bool:
        return s in self._tokens
    def check_text(self, text: str) -> bool:
        return any(t in text for t in self._tokens)
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "secrets", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    m = HoneytokenManager()
    t = m.create()
    assert m.is_honeytoken(t)
    assert m.check_text("leak " + t)
    assert not m.check_text("clean")
    assert stdlib_only()
    print("honeytokens OK")
if __name__ == "__main__": main()
