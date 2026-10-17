"""Small offline request-to-filesystem path traversal heuristic for Python.

This bounded, line-oriented pass follows simple assignments from common web
request fields to common filesystem APIs. It does not parse Python, resolve
imports or aliases, model scopes, or prove that path containment is enforced.
"""
from __future__ import annotations

import re
from typing import Any

from python_ssrf_sast import (
    _ASSIGNMENT,
    _REQUEST_SOURCE,
    _call_arguments,
    _references_variable,
)


RULE_ID = "PY012_PATH_TRAVERSAL"
SEVERITY = "high"
MESSAGE = "request-derived value used as a filesystem path"
REMEDIATION = (
    "Map user-facing identifiers to server-owned paths or resolve paths under a trusted root; "
    "enforce containment after symlink resolution and use race-safe file opens."
)
_MAX_SOURCE_BYTES = 1024 * 1024
_PATH_METHODS = (
    "open|read_text|read_bytes|write_text|write_bytes|unlink|rmdir|rename|replace|"
    "mkdir|touch|iterdir|glob|rglob|exists|is_file|is_dir"
)
_FILE_CALL = re.compile(
    r"(?:\b(?:builtins|io|aiofiles)\s*\.\s*open|(?<![\w.])open"
    r"|\bos\s*\.\s*(?:open|remove|unlink|rmdir|rename|replace|mkdir|makedirs|listdir|scandir)"
    r"|\bshutil\s*\.\s*(?:copy|copyfile|copy2|copytree|move|rmtree)"
    r"|\b(?:send_file|FileResponse))\s*\("
)
_PATH_OBJECT_CALL = re.compile(
    rf"\b(?P<receiver>[A-Za-z_]\w*)\s*\.\s*(?P<method>{_PATH_METHODS})\s*\("
)
_PATH_CONSTRUCTOR_METHOD = re.compile(
    rf"\b(?:(?:pathlib\s*\.\s*)?Path)\s*\((?P<path_expr>.+)\)\s*\.\s*"
    rf"(?P<method>{_PATH_METHODS})\s*\("
)
_PATH_KEYWORDS = {
    "file", "filename", "name", "path", "path_or_file", "src", "source", "dst", "destination"
}


def _tainted_reference(expression: str, tainted_variables: set[str]) -> tuple[str | None, int]:
    source_match = _REQUEST_SOURCE.search(expression)
    if source_match is not None:
        return None, source_match.start()
    variable = next((
        name for name in sorted(tainted_variables)
        if _references_variable(expression, name)
    ), None)
    return variable, expression.find(variable) if variable is not None else -1


def _finding(line_number: int, column: int) -> dict[str, Any]:
    return {
        "rule": RULE_ID,
        "severity": SEVERITY,
        "message": MESSAGE,
        "remediation": REMEDIATION,
        "line": line_number,
        "column": max(1, column),
    }


def scan_source(source: Any) -> list[dict[str, Any]]:
    """Return heuristic request-to-filesystem-path findings for Python source."""
    if not isinstance(source, str):
        raise TypeError("source must be a string")
    if len(source.encode("utf-8")) > _MAX_SOURCE_BYTES:
        raise ValueError("source exceeds the 1 MiB scan limit")

    findings: list[dict[str, Any]] = []
    tainted_variables: set[str] = set()
    for line_number, line in enumerate(source.splitlines(), start=1):
        assignment = _ASSIGNMENT.match(line)
        assignment_value = assignment.group("value") if assignment else ""
        assignment_is_sink = bool(
            _FILE_CALL.search(assignment_value)
            or _PATH_OBJECT_CALL.search(assignment_value)
            or _PATH_CONSTRUCTOR_METHOD.search(assignment_value)
        )
        if assignment and not assignment_is_sink:
            name = assignment.group("name")
            value = assignment_value
            if _REQUEST_SOURCE.search(value) or any(
                _references_variable(value, variable) for variable in tainted_variables
            ):
                tainted_variables.add(name)
            else:
                tainted_variables.discard(name)

        for sink in _FILE_CALL.finditer(line):
            name = sink.group(0).split("(", 1)[0].strip().rsplit(".", 1)[-1].strip()
            arguments = _call_arguments(line, sink.end())
            selected_indices = (0, 1) if name in {
                "rename", "replace", "copy", "copyfile", "copy2", "copytree", "move"
            } else (0,)
            selected_arguments = [
                (argument, offset) for index, (argument, offset) in enumerate(arguments)
                if index in selected_indices
                or argument.partition("=")[0].strip() in _PATH_KEYWORDS
            ]
            for expression, expression_start in selected_arguments:
                _, offset = _tainted_reference(expression, tainted_variables)
                if offset >= 0:
                    findings.append(_finding(line_number, expression_start + offset + 1))

        for call in _PATH_OBJECT_CALL.finditer(line):
            receiver = call.group("receiver")
            if receiver in tainted_variables:
                findings.append(_finding(line_number, call.start("receiver") + 1))
            if call.group("method") in {"rename", "replace"}:
                arguments = _call_arguments(line, call.end())
                if arguments:
                    expression, expression_start = arguments[0]
                    _, offset = _tainted_reference(expression, tainted_variables)
                    if offset >= 0:
                        findings.append(_finding(line_number, expression_start + offset + 1))

        for call in _PATH_CONSTRUCTOR_METHOD.finditer(line):
            expression = call.group("path_expr")
            _, offset = _tainted_reference(expression, tainted_variables)
            if offset >= 0:
                findings.append(_finding(line_number, call.start("path_expr") + offset + 1))
            if call.group("method") in {"rename", "replace"}:
                arguments = _call_arguments(line, call.end())
                if arguments:
                    target, target_start = arguments[0]
                    _, target_offset = _tainted_reference(target, tainted_variables)
                    if target_offset >= 0:
                        findings.append(_finding(line_number, target_start + target_offset + 1))

        if assignment and assignment_is_sink:
            # The assigned value is file contents or an API result, not a path alias.
            tainted_variables.discard(assignment.group("name"))

    return findings


__all__ = ["MESSAGE", "REMEDIATION", "RULE_ID", "SEVERITY", "scan_source"]
