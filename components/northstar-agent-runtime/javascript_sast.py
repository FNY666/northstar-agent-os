"""Small offline JavaScript/TypeScript security rule set.

This is a bounded line-pattern scanner, not a JavaScript parser or full
dataflow engine. It reports common dangerous APIs and configurations without
importing, building, or executing the scanned project. Small within-file taint
passes track request-derived values to outbound HTTP and filesystem sinks; they
do not model JavaScript scope, sanitizers, or multi-function flows.
"""
from __future__ import annotations

import re
from typing import Any


_FILE_PATH_METHODS = (
    "readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|"
    "open|openSync|unlink|unlinkSync|rm|rmSync|rmdir|rmdirSync|mkdir|mkdirSync|"
    "readdir|readdirSync|stat|statSync|lstat|lstatSync|access|accessSync|"
    "createReadStream|createWriteStream|realpath|realpathSync|rename|renameSync|"
    "copyFile|copyFileSync|cp|cpSync|link|symlink"
)
_FILE_PATH_SINK = re.compile(
    rf"\b(?:fs\s*(?:\.\s*promises\s*)?\.\s*(?P<fs_method>{_FILE_PATH_METHODS})"
    r"|(?:res|response)\s*\.\s*(?P<response_method>sendFile|download))\s*\("
)
_FILE_PATH_SOURCE = re.compile(
    r"\b(?:req|request)\s*\.\s*(?:query|params|body|headers|cookies|path)\b"
)
_FILE_PATH_TWO_ARGUMENT_SINKS = {
    "rename", "renameSync", "copyFile", "copyFileSync", "cp", "cpSync", "link", "symlink"
}


def _call_arguments(line: str, start: int) -> list[tuple[str, int]]:
    """Split one same-line call while respecting nested delimiters and strings."""
    arguments: list[tuple[str, int]] = []
    segment_start = start
    stack: list[str] = []
    pairs = {"(": ")", "[": "]", "{": "}"}
    quote: str | None = None
    escaped = False
    index = start
    while index < len(line):
        char = line[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in "'\"`":
            quote = char
        elif line.startswith("//", index):
            break
        elif char in pairs:
            stack.append(pairs[char])
        elif char in ")]}":
            if not stack:
                if char == ")":
                    raw = line[segment_start:index]
                    leading = len(raw) - len(raw.lstrip())
                    if raw.strip():
                        arguments.append((raw.strip(), segment_start + leading))
                break
            if char == stack[-1]:
                stack.pop()
        elif char == "," and not stack:
            raw = line[segment_start:index]
            leading = len(raw) - len(raw.lstrip())
            arguments.append((raw.strip(), segment_start + leading))
            segment_start = index + 1
        index += 1
    else:
        raw = line[segment_start:]
        leading = len(raw) - len(raw.lstrip())
        if raw.strip():
            arguments.append((raw.strip(), segment_start + leading))
    return arguments


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
        "Resolve outbound requests through a strict destination allowlist and reject private, "
        "loopback, and link-local addresses after DNS resolution.",
        re.compile(
            r"\b(?:fetch|got)\s*\(\s*(?:req|request)\s*\.\s*"
            r"(?:query|params|body|headers|cookies|path)\b"
            r"|\baxios\s*\.\s*(?:get|post|put|delete|request)\s*\(\s*"
            r"(?:req|request)\s*\.\s*(?:query|params|body|headers|cookies|path)\b"
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
    (
        "JS009_PATH_TRAVERSAL", "high", "request-derived value used as a filesystem path",
        "Constrain user-selected paths to a trusted root after resolution; reject traversal and "
        "symlink escapes, and use race-safe file APIs.",
        _FILE_PATH_SINK,
    ),
)
_RULE_BY_ID = {rule[0]: rule for rule in RULES}

_REQUEST_URL_SOURCE = re.compile(
    r"\b(?:req|request)\s*\.\s*(?:query|params|body|headers|cookies|path)\b"
)
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
    tainted_request_variables: set[str] = set()
    for line_no, line in enumerate(source.splitlines(), start=1):
        assignment = _ASSIGNMENT.match(line)
        if assignment:
            variable, expression = assignment.groups()
            # HTTP and filesystem responses are data, not aliases for their arguments.
            assignment_is_sink = bool(
                _OUTBOUND_URL_SINK.search(expression) or _FILE_PATH_SINK.search(expression)
            )
            if assignment_is_sink:
                tainted_request_variables.discard(variable)
            else:
                tainted = bool(
                    _REQUEST_URL_SOURCE.search(expression) or _FILE_PATH_SOURCE.search(expression)
                ) or any(
                    _references_variable(expression, name)
                    for name in tainted_request_variables
                )
                if tainted:
                    tainted_request_variables.add(variable)
                else:
                    tainted_request_variables.discard(variable)

        line_rules: set[str] = set()
        for rule, severity, message, remediation, pattern in RULES:
            match = pattern.search(line)
            if match:
                line_rules.add(rule)
                if rule == "JS009_PATH_TRAVERSAL":
                    # The filesystem pass below reports the tainted argument location.
                    continue
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
                if url_variable in tainted_request_variables:
                    findings.append({
                        "rule": "JS005_UNTRUSTED_SSRF",
                        "severity": _RULE_BY_ID["JS005_UNTRUSTED_SSRF"][1],
                        "message": _RULE_BY_ID["JS005_UNTRUSTED_SSRF"][2],
                        "remediation": _RULE_BY_ID["JS005_UNTRUSTED_SSRF"][3],
                        "line": line_no,
                        "column": (
                            sink.start("url_arg") + 1
                            if sink.group("url_arg")
                            else sink.start("axios_url_arg") + 1
                        ),
                    })
        for sink in _FILE_PATH_SINK.finditer(line):
            method = sink.group("fs_method") or sink.group("response_method")
            argument_indexes = (0, 1) if method in _FILE_PATH_TWO_ARGUMENT_SINKS else (0,)
            arguments = _call_arguments(line, sink.end())
            for index in argument_indexes:
                if index >= len(arguments):
                    continue
                expression, expression_start = arguments[index]
                source_match = _FILE_PATH_SOURCE.search(expression)
                tainted_variable = next((
                    variable for variable in sorted(tainted_request_variables)
                    if _references_variable(expression, variable)
                ), None)
                if source_match is None and tainted_variable is None:
                    continue
                offset = (
                    source_match.start()
                    if source_match is not None
                    else expression.find(tainted_variable or "")
                )
                findings.append({
                    "rule": "JS009_PATH_TRAVERSAL",
                    "severity": _RULE_BY_ID["JS009_PATH_TRAVERSAL"][1],
                    "message": _RULE_BY_ID["JS009_PATH_TRAVERSAL"][2],
                    "remediation": _RULE_BY_ID["JS009_PATH_TRAVERSAL"][3],
                    "line": line_no,
                    "column": expression_start + offset + 1,
                })
    return findings


__all__ = ["RULES", "scan_source"]
