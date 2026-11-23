"""Canary tokens: deception for exfiltration detection (D-OUT-005), Simulated."""
from __future__ import annotations
import ast, secrets
from typing import Dict, List
VERSION = "canary-tokens.v1"
class CanaryVault:
    def __init__(self):
        self._tokens: Dict[str, str] = {}
    def plant(self, token_id: str) -> str:
        """Plant a canary token. Returns the token value."""
        val = f"CANARY-{secrets.token_hex(8)}"
        self._tokens[token_id] = val
        return val
    def check(self, text: str) -> List[str]:
        """Check if any canary token appears in text (exfiltration!)."""
        found = []
        for tid, val in self._tokens.items():
            if val in text:
                found.append(tid)
        return found
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
    v = CanaryVault()
    tok = v.plant("db1")
    assert v.check("leaked " + tok) == ["db1"]
    assert v.check("clean") == []
    assert stdlib_only()
    print("canary-tokens OK")
if __name__ == "__main__": main()
