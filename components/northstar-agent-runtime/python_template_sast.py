"""Bounded AST taint analysis for Python server-side template injection.

The scanner follows common request, CLI, environment, and interactive-input
sources into APIs that compile template source. Rendering user data through a
static template remains clear because values passed as render context are not
template source. This is a single-file heuristic and does not resolve custom
template wrappers, template files, or flows across function boundaries.
"""
from __future__ import annotations

import ast
from typing import Any

from python_command_sast import (
    _Analyzer,
    _Finding,
    _MAX_AST_NODES,
    _MAX_SOURCE_BYTES,
)


RULE_ID = "PY016_SERVER_SIDE_TEMPLATE_INJECTION"
SEVERITY = "high"
MESSAGE = "untrusted value reaches template compilation"
REMEDIATION = (
    "Keep template source in trusted files and pass untrusted values as render context. "
    "If users author templates, isolate rendering and enforce strict resource limits; "
    "autoescaping and sandboxing are defense in depth, not source validation."
)
_TEMPLATE_RENDERERS = {
    "flask.render_template_string",
}
_TEMPLATE_CONSTRUCTORS = {
    "jinja2.Template",
    "jinja2.environment.Template",
    "jinja2.sandbox.SandboxedEnvironment.from_string",
    "django.template.Template",
    "mako.template.Template",
}
class _TemplateAnalyzer(_Analyzer):
    @staticmethod
    def _is_template_sink(call: ast.Call, name: str | None) -> bool:
        if name in _TEMPLATE_RENDERERS | _TEMPLATE_CONSTRUCTORS:
            return True
        # Environment instances may be local variables or constructor calls, so
        # their type cannot always be recovered from the dotted AST name.
        return isinstance(call.func, ast.Attribute) and call.func.attr == "from_string"

    @staticmethod
    def _template_source(call: ast.Call, name: str | None) -> ast.AST | None:
        if name == "flask.render_template_string":
            keyword_names = {"source"}
        elif name in {"django.template.Template"}:
            keyword_names = {"template_string"}
        elif name in {"mako.template.Template"}:
            keyword_names = {"text"}
        else:
            # Jinja Template and Environment.from_string both accept source=.
            keyword_names = {"source"}
        for keyword in call.keywords:
            if keyword.arg in keyword_names:
                return keyword.value
        return call.args[0] if call.args else None

    def _call_sink(self, call: ast.Call, env: dict) -> None:
        name = self._canonical_name(call.func)
        if not self._is_template_sink(call, name):
            return
        source = self._template_source(call, name)
        origin = self._taint(source, env)
        if origin is None:
            return
        sink = name or "template.from_string"
        self.findings.append(_Finding(
            line=getattr(call, "lineno", 1),
            column=getattr(call, "col_offset", 0) + 1,
            source_line=origin.source_line,
            sink=sink,
        ))


def scan_source(source: Any) -> list[dict[str, Any]]:
    """Return untrusted-source-to-template-compilation flow findings."""
    if not isinstance(source, str):
        raise TypeError("source must be a string")
    if len(source.encode("utf-8")) > _MAX_SOURCE_BYTES:
        raise ValueError("source exceeds the 1 MiB scan limit")
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, TypeError, RecursionError):
        return []
    for node_count, _ in enumerate(ast.walk(tree), start=1):
        if node_count > _MAX_AST_NODES:
            return []
    try:
        analyzer = _TemplateAnalyzer(tree)
    except RecursionError:
        return []

    unique = {
        (finding.line, finding.column, finding.source_line, finding.sink): finding
        for finding in analyzer.findings
    }
    return [
        {
            "rule": RULE_ID,
            "severity": SEVERITY,
            "message": (
                f"untrusted value from line {finding.source_line} reaches template "
                f"compilation via {finding.sink}"
            ),
            "remediation": REMEDIATION,
            "line": finding.line,
            "column": finding.column,
        }
        for finding in sorted(unique.values(), key=lambda item: (item.line, item.column, item.sink))
    ]


__all__ = ["MESSAGE", "REMEDIATION", "RULE_ID", "SEVERITY", "scan_source"]
