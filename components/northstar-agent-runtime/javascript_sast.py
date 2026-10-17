"""Small offline JavaScript/TypeScript security rule set.

This is a bounded line-pattern scanner, not a JavaScript parser or full
dataflow engine. It reports common dangerous APIs and configurations without
importing, building, or executing the scanned project. A small within-file
taint pass tracks request-derived URL variables to outbound HTTP calls; it does
not model JavaScript scope, sanitizers, or multi-function flows.
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
        "JS005_UNTRUSTED_SSRF", "high", "request-derived value used as an outbound URL",
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
_RULE_BY_ID = {rule[0]: rule for rule in RULES}

_REQUEST_URL_SOURCE = re.compile(r"\b(?:req|request)\s*\.\s*(?:query|params|body|headers)\b")
_ASSIGNMENT = re.compile(
    r"^\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=(?!=|>)\s*(.*?)\s*;?\s*$"
)
_OUTBOUND_URL_SINK = re.compile(
    r"\b(?:fetch|got)\s*\(\s*(?P<url_arg>[A-Za-z_$][\w$]*)\b"
    r"|\baxios\s*\.\s*(?:get|post|put|delete|request)\s*\(\s*(?P<axios_url_arg>[A-Za-z_$][\w$]*)\b"
)


def _references_variable(expression: str, variable: str) -> bool:
    return re.search(rf"(?<![\w$.]){re.escape(variable)}(?![\w$])", expression) is not None


def scan_source(source: Any) -> list[dict[str, Any]]:
    """Return line-based findings for JavaScript/TypeScript source text."""
    if not isinstance(source, str):
        raise TypeError("source must be a string")
    findings: list[dict[str, Any]] = []
    tainted_url_variables: set[str] = set()
    for line_no, line in enumerate(source.splitlines(), start=1):
        assignment = _ASSIGNMENT.match(line)
        if assignment:
            variable, expression = assignment.groups()
            # A fetched response is data derived from the remote server, not an
            # alias for the URL argument. Keep this tiny flow model URL-focused.
            if _OUTBOUND_URL_SINK.search(expression) is None:
                tainted = bool(_REQUEST_URL_SOURCE.search(expression)) or any(
                    _references_variable(expression, name)
                    for name in tainted_url_variables
                )
                if tainted:
                    tainted_url_variables.add(variable)
                else:
                    tainted_url_variables.discard(variable)

        line_rules: set[str] = set()
        for rule, severity, message, remediation, pattern in RULES:
            match = pattern.search(line)
            if match:
                line_rules.add(rule)
                findings.append({
                    "rule": rule,
                    "severity": severity,
                    "message": message,
                    "remediation": remediation,
                    "line": line_no,
                    "column": match.start() + 1,
                })
        if "JS005_UNTRUSTED_SSRF" not in line_rules:
            sink = _OUTBOUND_URL_SINK.search(line)
            if sink:
                url_variable = sink.group("url_arg") or sink.group("axios_url_arg")
                if url_variable in tainted_url_variables:
                    findings.append({
                        "rule": "JS005_UNTRUSTED_SSRF",
                        "severity": _RULE_BY_ID["JS005_UNTRUSTED_SSRF"][1],
                        "message": _RULE_BY_ID["JS005_UNTRUSTED_SSRF"][2],
                        "remediation": _RULE_BY_ID["JS005_UNTRUSTED_SSRF"][3],
                        "line": line_no,
                        "column": sink.start("url_arg") + 1 if sink.group("url_arg") else sink.start("axios_url_arg") + 1,
                    })
    return findings


__all__ = ["RULES", "scan_source"]
