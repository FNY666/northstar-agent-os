"""Bounded checks for three high-risk Shell execution patterns.

This is deliberately a heuristic, not a Shell parser. It reports dynamic ``eval``,
dynamic ``sh -c`` strings, and direct remote-script pipelines while avoiding
copies of source text in output.
"""
from __future__ import annotations

import re
from typing import Any


_EVAL_EXPANSION = re.compile(r"(?i)(?:^|[;&|]\s*)eval\s+[^\n#]*\$(?:\{|[A-Za-z_])")
_REMOTE_PIPE = re.compile(
    r"(?i)(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b"
)
_DYNAMIC_COMMAND_STRING = re.compile(
    r"(?i)(?:^|[;&|]\s*)(?:command\s+)?(?:sh|bash|zsh)\s+-c\s+[^\n#]*\$(?:\{|[A-Za-z_])"
)


def scan_source(source: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    logical_lines: list[tuple[int, str]] = []
    pending = ""
    start_line = 1
    for line_number, raw_line in enumerate(source.splitlines(), start=1):
        if not pending:
            start_line = line_number
        # A trailing unescaped backslash joins the next physical line. Comment
        # handling stays intentionally conservative and line-oriented.
        code = raw_line.split("#", 1)[0].rstrip()
        continued = code.endswith("\\") and (len(code) - len(code.rstrip("\\"))) % 2 == 1
        if continued:
            pending += code[:-1] + " "
            continue
        logical_lines.append((start_line, pending + code))
        pending = ""
    if pending:
        logical_lines.append((start_line, pending))

    for line_number, code in logical_lines:
        checks = (
            (_EVAL_EXPANSION, "SH001_DYNAMIC_EVAL", "high", "shell evaluates a dynamically expanded command"),
            (_REMOTE_PIPE, "SH002_REMOTE_SCRIPT_PIPE", "high", "remote response is piped directly into a shell"),
            (_DYNAMIC_COMMAND_STRING, "SH003_DYNAMIC_COMMAND_STRING", "high", "shell executes a dynamically expanded command string"),
        )
        for pattern, rule, severity, message in checks:
            match = pattern.search(code)
            if match:
                findings.append({
                    "line": line_number,
                    "column": match.start() + 1,
                    "rule": rule,
                    "severity": severity,
                    "message": message,
                    "remediation": {
                        "SH001_DYNAMIC_EVAL": "Replace eval with explicit argument handling and a fixed operation map.",
                        "SH002_REMOTE_SCRIPT_PIPE": "Download from a pinned, authenticated source, verify its digest or signature, then review before execution.",
                        "SH003_DYNAMIC_COMMAND_STRING": "Avoid sh -c/bash -c with expanded input; select a fixed executable and pass validated arguments directly.",
                    }[rule],
                })
    return findings
