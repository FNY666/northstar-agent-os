"""Small offline Python request-to-HTTP SSRF heuristic.

This bounded, line-oriented pass follows simple assignments from common web
request fields to common HTTP client URL arguments. It does not parse Python,
resolve imports or aliases, model scopes, or prove that a destination allowlist
is correct.
"""
from __future__ import annotations

import re
from typing import Any


RULE_ID = "PY011_UNTRUSTED_SSRF"
SEVERITY = "high"
MESSAGE = "request-derived value used as an outbound URL"
REMEDIATION = (
    "Resolve outbound requests through a strict destination allowlist and reject private, "
    "loopback, and link-local addresses after DNS resolution."
)
_MAX_SOURCE_BYTES = 1024 * 1024

_REQUEST_SOURCE = re.compile(
    r"\b(?:request|flask\s*\.\s*request)\s*\.\s*"
    r"(?:args|form|values|cookies|headers|files|GET|POST|query_params|path_params|json|data|url|path|path_info)\b"
)
_HTTP_SINK = re.compile(
    r"\b(?:(?:requests|httpx)\s*\.\s*(?P<module_method>"
    r"get|post|put|delete|head|options|patch|request)"
    r"|(?:session|client|http_client|httpx_client|aiohttp_session)\s*\.\s*(?P<object_method>"
    r"get|post|put|delete|head|options|patch|request)"
    r"|urllib\s*\.\s*request\s*\.\s*urlopen|urlopen)\s*\("
)
_ASSIGNMENT = re.compile(
    r"^\s*(?P<name>[A-Za-z_]\w*)\s*(?::\s*[^=]+)?=(?!=)\s*(?P<value>.*?)\s*$"
)


def _references_variable(expression: str, variable: str) -> bool:
    return re.search(rf"(?<![\w.]){re.escape(variable)}(?!\w)", expression) is not None


def _call_arguments(line: str, start: int) -> list[tuple[str, int]]:
    """Split a same-line call's arguments while respecting nested syntax and strings."""
    arguments: list[tuple[str, int]] = []
    segment_start = start
    stack: list[str] = []
    pairs = {"(": ")", "[": "]", "{": "}"}
    quote: str | None = None
    triple = False
    escaped = False
    index = start
    while index < len(line):
        char = line[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif triple and line.startswith(quote * 3, index):
                quote = None
                triple = False
                index += 2
            elif not triple and char == quote:
                quote = None
        elif char in "'\"":
            quote = char
            triple = line.startswith(char * 3, index)
            if triple:
                index += 2
        elif char == "#":
            break
        elif char in pairs:
            stack.append(pairs[char])
        elif char in ")]}":
            if not stack:
                if char == ")":
                    raw = line[segment_start:index]
                    leading = len(raw) - len(raw.lstrip())
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
        tail = line[segment_start:].strip()
        if tail:
            raw = line[segment_start:]
            leading = len(raw) - len(raw.lstrip())
            arguments.append((tail, segment_start + leading))
    if not arguments and line[start:].strip():
        arguments.append((line[start:].strip(), start))
    return arguments


def scan_source(source: Any) -> list[dict[str, Any]]:
    """Return heuristic request-to-outbound-HTTP findings for Python source."""
    if not isinstance(source, str):
        raise TypeError("source must be a string")
    if len(source.encode("utf-8")) > _MAX_SOURCE_BYTES:
        raise ValueError("source exceeds the 1 MiB scan limit")

    findings: list[dict[str, Any]] = []
    tainted_variables: set[str] = set()
    for line_number, line in enumerate(source.splitlines(), start=1):
        assignment = _ASSIGNMENT.match(line)
        assignment_sink = _HTTP_SINK.search(assignment.group("value")) if assignment else None
        if assignment and assignment_sink is None:
            name, value = assignment.group("name", "value")
            if (
                _REQUEST_SOURCE.search(value) or any(
                    _references_variable(value, variable)
                    for variable in tainted_variables
                )
            ):
                tainted_variables.add(name)
            else:
                tainted_variables.discard(name)

        for sink in _HTTP_SINK.finditer(line):
            method = sink.group("module_method") or sink.group("object_method")
            arguments = _call_arguments(line, sink.end())
            url_argument_index = 1 if method == "request" else 0
            if len(arguments) <= url_argument_index:
                continue
            expression, expression_start = arguments[url_argument_index]
            source_match = _REQUEST_SOURCE.search(expression)
            tainted_variable = next((
                variable for variable in sorted(tainted_variables)
                if _references_variable(expression, variable)
            ), None)
            if source_match is None and tainted_variable is None:
                continue
            offset = source_match.start() if source_match is not None else expression.find(tainted_variable or "")
            findings.append({
                "rule": RULE_ID,
                "severity": SEVERITY,
                "message": MESSAGE,
                "remediation": REMEDIATION,
                "line": line_number,
                "column": max(1, expression_start + offset + 1),
            })
        if assignment and assignment_sink is not None:
            # The assigned value is an HTTP response, not an alias of its URL.
            tainted_variables.discard(assignment.group("name"))
    return findings


__all__ = ["MESSAGE", "REMEDIATION", "RULE_ID", "SEVERITY", "scan_source"]
