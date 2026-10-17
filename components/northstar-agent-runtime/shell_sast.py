"""Bounded line-level checks for two high-risk Shell execution patterns.

This is deliberately a heuristic, not a Shell parser. It reports dynamic ``eval``
and direct remote-script pipelines while avoiding copies of source text in output.
"""
from __future__ import annotations

import re
from typing import Any


_EVAL_EXPANSION = re.compile(r"(?i)(?:^|[;&|]\s*)eval\s+[^\n#]*\$(?:\{|[A-Za-z_])")
_REMOTE_PIPE = re.compile(
    r"(?i)(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b"
)


def scan_source(source: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        code = line.split("#", 1)[0]
        checks = (
            (_EVAL_EXPANSION, "SH001_DYNAMIC_EVAL", "high", "shell evaluates a dynamically expanded command"),
            (_REMOTE_PIPE, "SH002_REMOTE_SCRIPT_PIPE", "high", "remote response is piped directly into a shell"),
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
                    "remediation": (
                        "Replace eval with explicit argument handling and a fixed operation map."
                        if rule == "SH001_DYNAMIC_EVAL"
                        else "Download from a pinned, authenticated source, verify its digest or signature, then review before execution."
                    ),
                })
    return findings
