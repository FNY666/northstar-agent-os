"""DLP integration: data loss prevention interface (D-OUT-003), Simulated."""
from __future__ import annotations
import ast
from typing import Dict, List
VERSION = "dlp-interface.v1"
class DLPError(Exception): pass
class DLPPolicy:
    def __init__(self, name: str, patterns: List[str], action: str = "block"):
        self.name = name
        self.patterns = patterns
        self.action = action
    def check(self, text: str) -> Dict:
        import re
        for pat in self.patterns:
            if re.search(pat, text, re.IGNORECASE):
                return {"violated": True, "policy": self.name, "action": self.action}
        return {"violated": False}
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
    p = DLPPolicy("no_ssn", [r"\d{3}-\d{2}-\d{4}"])
    assert p.check("SSN 123-45-6789")["violated"] is True
    assert p.check("hello")["violated"] is False
    assert stdlib_only()
    print("dlp-interface OK")
if __name__ == "__main__": main()
