"""Bounded AST taint analysis for Python SQL injection flows.

The scanner follows common request, CLI, environment, and interactive-input
sources through assignments and expressions into database ``execute`` APIs.
Parameterized queries remain clear when untrusted values are passed only as
separate parameters. This is a single-file heuristic: it does not follow
interprocedural flows or prove that a database driver's query builder is safe.
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


RULE_ID = "PY014_SQL_INJECTION_FLOW"
SEVERITY = "high"
MESSAGE = "untrusted value reaches a SQL query"
REMEDIATION = (
    "Use parameterized queries and pass user-controlled values separately from SQL text; "
    "allowlist identifiers that cannot be bound as parameters."
)
_SQL_METHODS = {"execute", "executemany", "exec_driver_sql", "executescript"}
_QUERY_KEYWORDS = {"sql", "query", "statement", "stmt"}


class _SqlAnalyzer(_Analyzer):
    @staticmethod
    def _query_argument(call: ast.Call) -> ast.AST | None:
        if not isinstance(call.func, ast.Attribute) or call.func.attr not in _SQL_METHODS:
            return None
        query = next((
            keyword.value for keyword in call.keywords if keyword.arg in _QUERY_KEYWORDS
        ), None)
        if query is not None:
            return query
        return call.args[0] if call.args else None

    def _call_sink(self, call: ast.Call, env: dict) -> None:
        query = self._query_argument(call)
        if query is None:
            return
        origin = self._taint(query, env)
        if origin is not None:
            self.findings.append(_Finding(
                line=getattr(call, "lineno", 1),
                column=getattr(call, "col_offset", 0) + 1,
                source_line=origin.source_line,
                sink=f".{call.func.attr}",
            ))

    def _taint(self, node: ast.AST | None, env: dict):
        if isinstance(node, ast.Call) and self._query_argument(node) is not None:
            # A database API's result is not the SQL text it consumed.
            return None
        return super()._taint(node, env)


def scan_source(source: Any) -> list[dict[str, Any]]:
    """Return source-to-SQL query flow findings."""
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
        analyzer = _SqlAnalyzer(tree)
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
                f"untrusted value from line {finding.source_line} reaches SQL execution "
                f"via {finding.sink}"
            ),
            "remediation": REMEDIATION,
            "line": finding.line,
            "column": finding.column,
        }
        for finding in sorted(unique.values(), key=lambda item: (item.line, item.column, item.sink))
    ]


__all__ = ["MESSAGE", "REMEDIATION", "RULE_ID", "SEVERITY", "scan_source"]
