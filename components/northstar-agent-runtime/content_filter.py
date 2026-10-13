"""Content filtering: blocklist (D-OUT-008), Simulated."""
from __future__ import annotations
import ast, re
from typing import List
VERSION = "content-filter.v1"
class ContentFilter:
    def __init__(self, blocklist: List[str] = None):
        self.blocklist = [re.compile(p, re.IGNORECASE) for p in (blocklist or [])]
    def check(self, text: str) -> tuple[bool, str]:
        for pat in self.blocklist:
            if pat.search(text):
                return False, f"blocked: {pat.pattern}"
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
    f = ContentFilter([r"badword"])
    assert f.check("hello")[0]
    assert not f.check("badword here")[0]
    assert stdlib_only()
    print("content-filter OK")
if __name__ == "__main__": main()
