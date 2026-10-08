"""Regex blocklist engine (D-IN-001), Simulated."""
from __future__ import annotations
import ast, re
from typing import List
VERSION = "regex-block.v1"
class Blocklist:
    def __init__(self, patterns: List[str]):
        self.patterns = [re.compile(p, re.IGNORECASE) for p in patterns]
    def check(self, text: str) -> tuple[bool, str]:
        for pat in self.patterns:
            if pat.search(text): return False, pat.pattern
        return True, "ok"
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
    b = Blocklist([r"evil", r"rm\s+-rf"])
    assert not b.check("do evil")[0]
    assert b.check("hello")[0]
    assert stdlib_only()
    print("regex-block OK")
if __name__ == "__main__": main()
