"""Bounded AST taint analysis for Python server-side request forgery flows.

The scanner follows common request, CLI, environment, and interactive-input
sources into outbound HTTP client URL arguments. It recognizes common import
aliases and multiline calls, and follows bounded direct calls to same-file
top-level helpers and explicitly named methods in top-level classes, including
simple local `self` / `cls` aliases. It does not resolve inherited or dynamic
method dispatch or cross-file flows, and cannot prove that a destination
allowlist is correct.
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


RULE_ID = "PY011_UNTRUSTED_SSRF"
SEVERITY = "high"
MESSAGE = "request-derived value used as an outbound URL"
REMEDIATION = (
    "Resolve outbound requests through a strict destination allowlist and reject private, "
    "loopback, and link-local addresses after DNS resolution."
)
_HTTP_METHODS = {
    "get", "post", "put", "delete", "head", "options", "patch", "request",
}
_HTTP_MODULES = ("requests.", "httpx.", "urllib3.")
_HTTP_CLIENT_NAMES = {
    "session", "client", "http_client", "httpx_client", "aiohttp_session",
}
_HTTP_CLIENT_CONSTRUCTORS = {
    "requests.Session",
    "requests.sessions.Session",
    "httpx.Client",
    "httpx.AsyncClient",
    "aiohttp.ClientSession",
    "urllib3.PoolManager",
}
_URL_OPENERS = {
    "urlopen",
    "urllib.urlopen",
    "urllib.request.urlopen",
}


class _SsrfAnalyzer(_Analyzer):
    def _is_http_sink(self, call: ast.Call) -> tuple[str, str] | None:
        name = self._canonical_name(call.func)
        if name in _URL_OPENERS:
            return name, "urlopen"
        method = (
            call.func.attr if isinstance(call.func, ast.Attribute)
            else name.rsplit(".", 1)[-1] if name else ""
        )
        if method not in _HTTP_METHODS:
            return None
        if name and name.startswith(_HTTP_MODULES):
            return name, method

        if isinstance(call.func, ast.Attribute):
            receiver = call.func.value
            if isinstance(receiver, ast.Name) and receiver.id in _HTTP_CLIENT_NAMES:
                return name or f"{receiver.id}.{method}", method
            if isinstance(receiver, ast.Call):
                constructor = self._canonical_name(receiver.func)
                if constructor in _HTTP_CLIENT_CONSTRUCTORS:
                    return f"{constructor}.{method}", method
        return None

    @staticmethod
    def _url_argument(call: ast.Call, method: str) -> ast.AST | None:
        keyword = next((item.value for item in call.keywords if item.arg == "url"), None)
        if keyword is not None:
            return keyword
        index = 1 if method == "request" else 0
        return call.args[index] if len(call.args) > index else None

    def _taint(self, node: ast.AST | None, env: dict):
        if isinstance(node, ast.Call) and self._is_http_sink(node) is not None:
            # An HTTP response is not an alias of the URL used to fetch it.
            return None
        return super()._taint(node, env)

    def _call_sink(self, call: ast.Call, env: dict) -> None:
        sink = self._is_http_sink(call)
        if sink is None:
            return
        name, method = sink
        url = self._url_argument(call, method)
        origin = self._taint(url, env)
        if origin is not None:
            self.findings.append(_Finding(
                line=getattr(call, "lineno", 1),
                column=getattr(call, "col_offset", 0) + 1,
                source_line=origin.source_line,
                sink=name,
            ))


def scan_source(source: Any) -> list[dict[str, Any]]:
    """Return untrusted-source-to-outbound-HTTP flow findings."""
    if not isinstance(source, str):
        raise TypeError("source must be a string")
    if len(source.encode("utf-8")) > _MAX_SOURCE_BYTES:
        raise ValueError("source exceeds the 1 MiB scan limit")
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, TypeError, RecursionError):
        return []
    if sum(1 for _ in ast.walk(tree)) > _MAX_AST_NODES:
        return []
    try:
        analyzer = _SsrfAnalyzer(tree)
    except RecursionError:
        return []

    unique = {
        (item.line, item.column, item.source_line, item.sink): item
        for item in analyzer.findings
    }
    return [
        {
            "rule": RULE_ID,
            "severity": SEVERITY,
            "message": (
                f"untrusted value from line {item.source_line} reaches outbound HTTP "
                f"request via {item.sink}"
            ),
            "remediation": REMEDIATION,
            "line": item.line,
            "column": item.column,
        }
        for item in sorted(unique.values(), key=lambda finding: (finding.line, finding.column, finding.sink))
    ]


__all__ = ["MESSAGE", "REMEDIATION", "RULE_ID", "SEVERITY", "scan_source"]
