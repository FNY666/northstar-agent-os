"""ML classifier sidecar mock (D-IN-002), Simulated."""
from __future__ import annotations
import ast
VERSION = "ml-sidecar.v1"
def classify(text: str) -> float:
    bad = ["evil", "attack", "inject"]
    return 0.9 if any(b in text.lower() for b in bad) else 0.1
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
    assert classify("evil attack") > 0.5
    assert classify("hello") < 0.5
    assert stdlib_only()
    print("ml-sidecar OK")
if __name__ == "__main__": main()
