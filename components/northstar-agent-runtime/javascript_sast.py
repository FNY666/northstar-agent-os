"""Small offline JavaScript/TypeScript security rule set.

This is a bounded line-pattern scanner, not a JavaScript parser or dataflow
engine. It reports common dangerous APIs and configurations without importing,
building, or executing the scanned project.
"""
from __future__ import annotations

import re
from typing import Any


RULES: tuple[tuple[str, str, str, str, re.Pattern[str]], ...] = (
    (
        "JS001_DYNAMIC_CODE", "critical", "dynamic code execution",
        "Avoid eval() and the Function constructor; use an explicit operation map or parser.",
        re.compile(r"\beval\s*\(|\bnew\s+Function\s*\("),
    ),
    (
        "JS002_SHELL_EXEC", "high", "shell command execution",
        "Avoid exec/execSync for values influenced by input; use a fixed executable with an argument array and validate each argument.",
        re.compile(
            r"\b(?:child_process|cp)\s*\.\s*(?:exec|execSync)\s*\("
            r"|\b(?:exec|execSync)\s*\([^\n;]*(?:\breq\.|\brequest\.|process\.env|\$\{)"
            r"|\b(?:spawn|spawnSync)\s*\([^\n;]*\bshell\s*:\s*true\b"
        ),
    ),
    (
        "JS003_SQL_INTERPOLATION", "high", "interpolated SQL query",
        "Use parameterized queries and bind user-controlled values as parameters.",
        re.compile(
            r"\b(?:pool|client|db|connection|sequelize)\s*\.\s*(?:query|execute)\s*\(\s*`[^`]*\$\{"
            r"|\b(?:query|sql)\s*=\s*`[^`]*\$\{"
        ),
    ),
    (
        "JS004_HTML_INJECTION", "high", "HTML injection sink",
        "Render untrusted content as text; if HTML is required, use a maintained sanitizer with a narrow allowlist.",
        re.compile(r"\.\s*innerHTML\s*=|\.\s*insertAdjacentHTML\s*\("),
    ),
    (
        "JS005_DIRECT_SSRF", "high", "request input used as an outbound URL",
        "Resolve outbound requests through a strict destination allowlist and reject private, loopback, and link-local addresses after DNS resolution.",
        re.compile(
            r"\b(?:fetch|got)\s*\(\s*(?:req|request)\s*\.\s*(?:query|params|body|headers)\b"
            r"|\baxios\s*\.\s*(?:get|post|put|delete|request)\s*\(\s*(?:req|request)\s*\.\s*(?:query|params|body|headers)\b"
        ),
    ),
    (
        "JS006_TLS_VERIFY_DISABLED", "high", "TLS certificate verification disabled",
        "Keep certificate verification enabled; configure a trusted CA bundle instead of disabling validation.",
        re.compile(r"\brejectUnauthorized\s*:\s*false\b"),
    ),
    (
        "JS007_WEAK_SECRET_RANDOM", "medium", "Math.random used for a security token",
        "Generate secrets and security tokens with node:crypto randomBytes or the Web Crypto API.",
        re.compile(r"\b(?:token|secret|nonce|csrf|session|apiKey)\w*\s*=.*\bMath\s*\.\s*random\s*\("),
    ),
    (
        "JS008_JWT_NONE_ALGORITHM", "critical", "JWT verification accepts the none algorithm",
        "Pin JWT verification to an explicit allowlist of signed algorithms and validate issuer and audience.",
        re.compile(r"\balgorithms\s*:\s*\[\s*['\"]none['\"]", re.IGNORECASE),
    ),
)


def scan_source(source: Any) -> list[dict[str, Any]]:
    """Return line-based findings for JavaScript/TypeScript source text."""
    if not isinstance(source, str):
        raise TypeError("source must be a string")
    findings: list[dict[str, Any]] = []
    for line_no, line in enumerate(source.splitlines(), start=1):
        for rule, severity, message, remediation, pattern in RULES:
            match = pattern.search(line)
            if match:
                findings.append({
                    "rule": rule,
                    "severity": severity,
                    "message": message,
                    "remediation": remediation,
                    "line": line_no,
                    "column": match.start() + 1,
                })
    return findings


__all__ = ["RULES", "scan_source"]
