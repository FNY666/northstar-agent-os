"""Safe completion: fallback responses (D-OUT-018), Simulated."""
from __future__ import annotations
import ast
VERSION = "safe-completion.v1"
FALLBACKS = {
    "refusal": "I can't help with that.",
    "error": "An error occurred. Please try again.",
    "empty": "No output generated.",
}
def safe_complete(blocked: bool, reason: str = "") -> str:
    if blocked:
        return FALLBACKS["refusal"]
    return FALLBACKS["empty"]
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
    assert "can't" in safe_complete(True)
    assert stdlib_only()
    print("safe-completion OK")
if __name__ == "__main__": main()
