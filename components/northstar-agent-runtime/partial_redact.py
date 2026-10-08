"""Partial redaction (D-OUT-019), Simulated."""
from __future__ import annotations
import ast
VERSION = "partial-redact.v1"
def redact_segment(text: str, start: int, end: int) -> str:
    return text[:start] + "[REDACTED]" + text[end:]
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
    assert redact_segment("hello world", 0, 5) == "[REDACTED] world"
    assert stdlib_only()
    print("partial-redact OK")
if __name__ == "__main__": main()
