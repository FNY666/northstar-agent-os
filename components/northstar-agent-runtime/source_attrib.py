"""Source attribution (D-OUT-014), Simulated."""
from __future__ import annotations
import ast
from typing import List, Dict
VERSION = "source-attrib.v1"
class Attributor:
    def __init__(self):
        self._sources: List[Dict] = []
    def add(self, uri: str, content_hash: str):
        self._sources.append({"uri": uri, "hash": content_hash})
    def attributions(self) -> List[Dict]:
        return list(self._sources)
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
    a = Attributor()
    a.add("https://x.com", "sha256:abc")
    assert len(a.attributions()) == 1
    assert stdlib_only()
    print("source-attrib OK")
if __name__ == "__main__": main()
