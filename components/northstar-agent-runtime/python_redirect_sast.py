"""Bounded AST taint analysis for Python open-redirect flows.

The scanner follows common request, CLI, environment, and interactive-input
sources into framework redirect helpers. It treats relative and absolute
destinations alike because attacker-controlled protocol-relative URLs can also
redirect off-site. This is a single-file heuristic: it follows bounded direct
calls to same-file top-level helpers and explicitly named methods in top-level
classes, including simple local `self` / `cls` aliases. It does not resolve
inherited or dynamic method dispatch or cross-file calls, or prove a destination
allowlist.
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


RULE_ID = "PY018_OPEN_REDIRECT_FLOW"
SEVERITY = "medium"
MESSAGE = "untrusted value reaches a redirect destination"
REMEDIATION = (
    "Use a server-owned route name or map user choices through a strict allowlist. "
    "Do not redirect directly to request parameters, headers, or other untrusted URLs."
)
_REDIRECT_SINKS = {
    "flask.redirect",
    "werkzeug.utils.redirect",
    "django.shortcuts.redirect",
    "django.http.HttpResponseRedirect",
    "django.http.response.HttpResponseRedirect",
    "django.http.HttpResponsePermanentRedirect",
    "django.http.response.HttpResponsePermanentRedirect",
    "starlette.responses.RedirectResponse",
    "fastapi.responses.RedirectResponse",
}
_REDIRECT_KEYWORDS = {"location", "to", "url", "redirect_to"}
_SAFE_REDIRECT_BUILDERS = {
    "flask.url_for",
    "django.urls.reverse",
}


class _RedirectAnalyzer(_Analyzer):
    @staticmethod
    def _redirect_sink_data(call: ast.Call) -> ast.AST | None:
        keyword = next((
            item.value for item in call.keywords if item.arg in _REDIRECT_KEYWORDS
        ), None)
        return keyword if keyword is not None else (call.args[0] if call.args else None)

    def _taint(self, node: ast.AST | None, env: dict):
        if isinstance(node, ast.Call):
            name = self._canonical_name(node.func)
            if name in _SAFE_REDIRECT_BUILDERS | _REDIRECT_SINKS:
                # A route builder returns a server-relative URL; a redirect
                # helper returns a response object rather than its location.
                return None
        return super()._taint(node, env)

    def _call_sink(self, call: ast.Call, env: dict) -> None:
        name = self._canonical_name(call.func)
        if name not in _REDIRECT_SINKS:
            return
        origin = self._taint(self._redirect_sink_data(call), env)
        if origin is not None:
            self.findings.append(_Finding(
                line=getattr(call, "lineno", 1),
                column=getattr(call, "col_offset", 0) + 1,
                source_line=origin.source_line,
                sink=name,
            ))


def scan_source(source: Any) -> list[dict[str, Any]]:
    """Return untrusted-source-to-redirect flow findings."""
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
        analyzer = _RedirectAnalyzer(tree)
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
                f"untrusted value from line {finding.source_line} reaches redirect "
                f"via {finding.sink}"
            ),
            "remediation": REMEDIATION,
            "line": finding.line,
            "column": finding.column,
        }
        for finding in sorted(unique.values(), key=lambda item: (item.line, item.column, item.sink))
    ]


__all__ = ["MESSAGE", "REMEDIATION", "RULE_ID", "SEVERITY", "scan_source"]
