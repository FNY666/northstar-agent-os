"""Hex decoding guard (D-IN-010), Simulated."""
from __future__ import annotations
import ast, re
VERSION = "hex-detect.v1"
def is_suspicious_hex(t: str) -> bool:
    if len(t) < 20: return False
    return bool(re.match(r"^[0-9a-fA-F]+$", t) and len(t) % 2 == 0)
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
    assert is_suspicious_hex("48656c6c6f20576f726c642121212121")
    assert not is_suspicious_hex("hello")
    assert stdlib_only()
    print("hex-detect OK")
if __name__ == "__main__": main()
