"""XXE detection (D-OUT-028), Simulated."""
from __future__ import annotations
import ast, re
VERSION = "xxe-detect.v1"
def detect(xml: str) -> bool:
    return bool(re.search(r"<!ENTITY", xml, re.IGNORECASE))
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
    assert detect('<!ENTITY xxe SYSTEM "file:///etc/passwd">')
    assert not detect("<root>hi</root>")
    assert stdlib_only()
    print("xxe-detect OK")
if __name__ == "__main__": main()
