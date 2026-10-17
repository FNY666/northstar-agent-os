"""Small offline Go request-to-network and request-to-filesystem heuristics.

This bounded, line-oriented pass follows simple assignments within one file.
It does not parse Go, resolve imports or aliases, model scopes, or understand
sanitizers and multi-line calls.
"""
from __future__ import annotations

import re
from typing import Any


SSRF_RULE_ID = "GO001_UNTRUSTED_SSRF"
PATH_RULE_ID = "GO002_PATH_TRAVERSAL"
_MAX_SOURCE_BYTES = 1024 * 1024
_REQUEST_SOURCE = re.compile(
    r"\b(?:r|req|request)\s*\.\s*(?:URL\s*\.\s*(?:Query\s*\(|Path\b|RawPath\b|"
    r"EscapedPath\s*\()|"
    r"FormValue\s*\(|PostFormValue\s*\(|Header\s*\.\s*Get\s*\(|PathValue\s*\()"
    r"|\b(?:chi\s*\.\s*URLParam|mux\s*\.\s*Vars)\s*\("
    r"|\b(?:c|ctx|ginCtx)\s*\.\s*(?:Query|QueryParam|Param|Params|PostForm|"
    r"PostFormValue|FormValue|GetHeader)\s*\("
)
_ASSIGNMENT = re.compile(
    r"^\s*(?:(?:var|const)\s+)?(?P<name>[A-Za-z_]\w*)"
    r"(?:\s*,\s*[A-Za-z_]\w*)*\s*(?::=|=(?!=))\s*(?P<value>.*?)\s*$"
)
_HTTP_SINK = re.compile(
    r"\b(?:http\s*\.\s*(?P<package_method>Get|Post|PostForm|Head)"
    r"|(?:http\s*\.\s*DefaultClient|client|[A-Za-z_]\w*[Cc]lient|hc)\s*\.\s*"
    r"(?P<client_method>Get|Post|Head|Do))\s*\("
)
_FILE_METHODS = (
    "Open|ReadFile|WriteFile|Create|OpenFile|Remove|RemoveAll|Stat|Lstat|"
    "Mkdir|MkdirAll|Chmod|Chown|Rename|Link|Symlink|TempFile|TempDir"
)
_FILE_SINK = re.compile(
    rf"\b(?:(?:os|ioutil)\s*\.\s*(?P<file_method>{_FILE_METHODS})"
    r"|http\s*\.\s*(?P<http_method>ServeFile|Dir))\s*\("
)
_TWO_PATH_FILE_METHODS = {"Rename", "Link", "Symlink"}


def _references_variable(expression: str, variable: str) -> bool:
    return re.search(rf"(?<![\w.]){re.escape(variable)}(?!\w)", expression) is not None


def _tainted_reference(expression: str, tainted_variables: set[str]) -> tuple[str | None, int]:
    source_match = _REQUEST_SOURCE.search(expression)
    if source_match is not None:
        return None, source_match.start()
    variable = next((
        name for name in sorted(tainted_variables)
        if _references_variable(expression, name)
    ), None)
    return variable, expression.find(variable) if variable is not None else -1


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


def _finding(rule: str, line_number: int, column: int) -> dict[str, Any]:
    if rule == SSRF_RULE_ID:
        message = "request-derived value used as an outbound URL"
        remediation = (
            "Resolve outbound requests through a strict destination allowlist and reject private, "
            "loopback, and link-local addresses after DNS resolution."
        )
    else:
        message = "request-derived value used as a filesystem path"
        remediation = (
            "Constrain user-selected paths to a trusted root after resolution; reject traversal "
            "and symlink escapes, and use race-safe file APIs."
        )
    return {
        "rule": rule,
        "severity": "high",
        "message": message,
        "remediation": remediation,
        "line": line_number,
        "column": max(1, column),
    }


def scan_source(source: Any) -> list[dict[str, Any]]:
    """Return heuristic Go SSRF and path traversal findings."""
    if not isinstance(source, str):
        raise TypeError("source must be a string")
    if len(source.encode("utf-8")) > _MAX_SOURCE_BYTES:
        raise ValueError("source exceeds the 1 MiB scan limit")

    findings: list[dict[str, Any]] = []
    tainted_variables: set[str] = set()
    for line_number, line in enumerate(source.splitlines(), start=1):
        assignment = _ASSIGNMENT.match(line)
        if assignment:
            name, value = assignment.group("name", "value")
            if _HTTP_SINK.search(value) or _FILE_SINK.search(value):
                # Network responses and file contents are not aliases of their paths.
                tainted_variables.discard(name)
            elif _REQUEST_SOURCE.search(value) or any(
                _references_variable(value, variable) for variable in tainted_variables
            ):
                tainted_variables.add(name)
            else:
                tainted_variables.discard(name)

        for sink in _HTTP_SINK.finditer(line):
            arguments = _call_arguments(line, sink.end())
            if not arguments:
                continue
            expression, expression_start = arguments[0]
            _, offset = _tainted_reference(expression, tainted_variables)
            if offset >= 0:
                findings.append(_finding(SSRF_RULE_ID, line_number, expression_start + offset + 1))

        for sink in _FILE_SINK.finditer(line):
            method = sink.group("file_method") or sink.group("http_method")
            if method == "ServeFile":
                argument_indices = (2,)
            elif method in _TWO_PATH_FILE_METHODS:
                argument_indices = (0, 1)
            else:
                argument_indices = (0,)
            arguments = _call_arguments(line, sink.end())
            for index in argument_indices:
                if index >= len(arguments):
                    continue
                expression, expression_start = arguments[index]
                _, offset = _tainted_reference(expression, tainted_variables)
                if offset >= 0:
                    findings.append(_finding(PATH_RULE_ID, line_number, expression_start + offset + 1))

    return findings


__all__ = ["PATH_RULE_ID", "SSRF_RULE_ID", "scan_source"]
