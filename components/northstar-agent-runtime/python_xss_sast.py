"""Bounded AST taint analysis for Python HTML output flows.

This rule follows common request, CLI, environment, and interactive-input
sources into raw HTML response constructors, strings returned from Flask route
handlers, and APIs that mark strings safe. It recognizes a small set of standard
HTML escapers, while static-template rendering remains outside its sink set. It
follows bounded direct calls to same-file top-level helpers and explicitly named
methods in top-level classes, including simple local `self` / `cls` aliases. It
does not resolve inherited or dynamic method dispatch, cross-file flows,
template filters, or output subcontexts.
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


RULE_ID = "PY017_XSS_OUTPUT_FLOW"
SEVERITY = "high"
MESSAGE = "untrusted value reaches an HTML output sink"
REMEDIATION = (
    "Use an autoescaping static template and pass values as context. For raw HTML, "
    "escape for the HTML context or sanitize with a maintained allowlist; do not use "
    "Markup or mark_safe on untrusted values."
)
_MARKUP_SINKS = {
    "markupsafe.Markup",
    "django.utils.safestring.mark_safe",
}
_HTML_RESPONSE_SINKS = {
    "flask.Response",
    "flask.wrappers.Response",
    "flask.make_response",
    "flask.helpers.make_response",
    "django.http.HttpResponse",
    "django.http.response.HttpResponse",
    "starlette.responses.HTMLResponse",
    "fastapi.responses.HTMLResponse",
}
_MEDIA_RESPONSE_SINKS = {
    "starlette.responses.Response",
    "fastapi.responses.Response",
}
_HTML_ESCAPERS = {
    "html.escape",
    "markupsafe.escape",
    "django.utils.html.escape",
}
_AUTOESCAPED_RENDERERS = {
    "flask.render_template",
    "flask.render_template_string",
    "django.shortcuts.render",
}
_NON_HTML_ROUTE_RESPONSES = {
    "flask.jsonify",
    "flask.json.jsonify",
    "django.http.JsonResponse",
    "django.http.response.JsonResponse",
    "starlette.responses.JSONResponse",
    "fastapi.responses.JSONResponse",
    "flask.redirect",
    "werkzeug.utils.redirect",
    "flask.send_file",
    "flask.send_from_directory",
}


def _keyword_value(call: ast.Call, names: set[str]) -> ast.AST | None:
    return next((keyword.value for keyword in call.keywords if keyword.arg in names), None)


def _is_html_media_type(node: ast.AST | None) -> bool | None:
    """Return whether a media type is HTML, or None when it is dynamic/unknown."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        media_type = node.value.partition(";")[0].strip().lower()
        return media_type in {"text/html", "application/xhtml+xml"}
    return None


class _XssAnalyzer(_Analyzer):
    def __init__(self, tree: ast.Module) -> None:
        self._in_flask_route = False
        super().__init__(tree)

    @staticmethod
    def _is_flask_route(decorator: ast.expr, analyzer: "_XssAnalyzer") -> bool:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = analyzer._canonical_name(target)
        return bool(name and name.rsplit(".", 1)[-1] == "route")

    def _route_return_sink(self, value: ast.AST | None, env: dict) -> None:
        if value is None:
            return
        if isinstance(value, ast.Call):
            name = self._canonical_name(value.func)
            if name and (
                name in _AUTOESCAPED_RENDERERS | _NON_HTML_ROUTE_RESPONSES
                | _MARKUP_SINKS | _HTML_RESPONSE_SINKS | _MEDIA_RESPONSE_SINKS
                or name.endswith(".TemplateResponse")
            ):
                return
        origin = self._taint(value, env)
        if origin is not None:
            self.findings.append(_Finding(
                line=getattr(value, "lineno", 1),
                column=getattr(value, "col_offset", 0) + 1,
                source_line=origin.source_line,
                sink="Flask route response",
            ))

    def _statements(self, statements: list[ast.stmt], env: dict) -> dict:
        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in statement.decorator_list:
                    self._expression(decorator, env)
                for default in (*statement.args.defaults, *statement.args.kw_defaults):
                    self._expression(default, env)
                is_route = any(
                    self._is_flask_route(decorator, self)
                    for decorator in statement.decorator_list
                )
                previous_route = self._in_flask_route
                self._in_flask_route = is_route
                try:
                    self._scoped(statement.body, env)
                finally:
                    self._in_flask_route = previous_route
            elif isinstance(statement, ast.Return) and self._in_flask_route:
                self._route_return_sink(statement.value, env)
                super()._statements([statement], env)
            else:
                super()._statements([statement], env)
        return env

    def _source_line(self, node: ast.AST) -> int | None:
        source_line = super()._source_line(node)
        if source_line is not None:
            return source_line
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"get_json", "get_data", "json", "body"}
        ):
            # Flask, Django, and Starlette expose request bodies through these
            # reader methods as well as through request attributes.
            return getattr(node, "lineno", 1)
        return None

    @staticmethod
    def _sink_name(call: ast.Call, name: str | None) -> str | None:
        if name in _MARKUP_SINKS | _HTML_RESPONSE_SINKS:
            return name
        if name not in _MEDIA_RESPONSE_SINKS:
            return None
        media_type = _keyword_value(call, {"media_type"})
        if media_type is None and len(call.args) > 3:
            media_type = call.args[3]
        if media_type is None:
            return None
        if _is_html_media_type(media_type) is False:
            return None
        return name

    @staticmethod
    def _sink_data(call: ast.Call, sink: str) -> ast.AST | None:
        if sink in _MARKUP_SINKS:
            return _keyword_value(call, {"base", "object", "s", "value"}) or (
                call.args[0] if call.args else None
            )
        if sink in {"flask.Response", "flask.wrappers.Response"}:
            media_type = _keyword_value(call, {"content_type", "mimetype"})
            if media_type is not None and _is_html_media_type(media_type) is False:
                return None
            return _keyword_value(call, {"response", "content"}) or (
                call.args[0] if call.args else None
            )
        if sink in {"django.http.HttpResponse", "django.http.response.HttpResponse"}:
            content_type = _keyword_value(call, {"content_type"})
            if content_type is None and len(call.args) > 1:
                content_type = call.args[1]
            if content_type is not None and _is_html_media_type(content_type) is False:
                return None
            return _keyword_value(call, {"content"}) or (call.args[0] if call.args else None)
        if sink in _MEDIA_RESPONSE_SINKS | {
            "starlette.responses.HTMLResponse", "fastapi.responses.HTMLResponse",
        }:
            return _keyword_value(call, {"content"}) or (call.args[0] if call.args else None)
        # Flask make_response() accepts response as either a keyword or first arg.
        return _keyword_value(call, {"response"}) or (call.args[0] if call.args else None)

    @staticmethod
    def _is_escaped(call: ast.Call, name: str | None) -> bool:
        if name not in _HTML_ESCAPERS:
            return False
        if name != "html.escape":
            return True
        quote = _keyword_value(call, {"quote"})
        if quote is None and len(call.args) > 1:
            quote = call.args[1]
        return not (isinstance(quote, ast.Constant) and quote.value is False)

    def _taint(self, node: ast.AST | None, env: dict):
        if isinstance(node, ast.Call):
            name = self._canonical_name(node.func)
            if (
                self._is_escaped(node, name)
                or name in _AUTOESCAPED_RENDERERS
                or name in _NON_HTML_ROUTE_RESPONSES
                or name in _MEDIA_RESPONSE_SINKS
                or (name is not None and name.endswith(".TemplateResponse"))
                or self._sink_name(node, name) is not None
            ):
                # Escaping removes taint; an output API's return value is a
                # rendered response, not the data it consumed.
                return None
        return super()._taint(node, env)

    def _call_sink(self, call: ast.Call, env: dict) -> None:
        name = self._canonical_name(call.func)
        sink = self._sink_name(call, name)
        if sink is None:
            return
        value = self._sink_data(call, sink)
        origin = self._taint(value, env)
        if origin is not None:
            self.findings.append(_Finding(
                line=getattr(call, "lineno", 1),
                column=getattr(call, "col_offset", 0) + 1,
                source_line=origin.source_line,
                sink=sink,
            ))


def scan_source(source: Any) -> list[dict[str, Any]]:
    """Return untrusted-source-to-HTML-output flow findings."""
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
        analyzer = _XssAnalyzer(tree)
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
                f"untrusted value from line {finding.source_line} reaches HTML output "
                f"via {finding.sink}"
            ),
            "remediation": REMEDIATION,
            "line": finding.line,
            "column": finding.column,
        }
        for finding in sorted(unique.values(), key=lambda item: (item.line, item.column, item.sink))
    ]


__all__ = ["MESSAGE", "REMEDIATION", "RULE_ID", "SEVERITY", "scan_source"]
