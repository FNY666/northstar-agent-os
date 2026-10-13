"""Secret scanning: detect secrets in output (D-OUT-002), Simulated."""
from __future__ import annotations
import ast, re
from typing import List, Dict
VERSION = "secret-scan.v1"
PATTERNS = {
    "aws_key": r"\bAKIA[0-9A-Z]{16}\b",
    "github_token": r"\bghp_[A-Za-z0-9]{36}\b",
    "slack_token": r"\bxox[baprs]-[A-Za-z0-9-]+\b",
    "private_key": r"-----BEGIN (?:RSA )?PRIVATE KEY-----",
    "generic_secret": r"\b(?:password|passwd|pwd|secret|token)\s*[:=]\s*\S+",
}
def scan(text: str) -> List[Dict[str, str]]:
    """Scan for secrets. Returns list of {type, match}."""
    findings = []
    for name, pattern in PATTERNS.items():
        for m in re.finditer(pattern, text, re.IGNORECASE):
            findings.append({"type": name, "match": m.group(0)[:20] + "..."})
    return findings
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "re", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    f = scan("AWS key: AKIAIOSFODNN7EXAMPLE")
    assert len(f) == 1 and f[0]["type"] == "aws_key"
    assert stdlib_only()
    print("secret-scan OK")
if __name__ == "__main__": main()
