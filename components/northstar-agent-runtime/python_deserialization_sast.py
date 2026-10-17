"""Bounded AST taint analysis for Python unsafe deserialization flows.

The scanner follows common request, CLI, environment, and interactive-input
sources into pickle-like APIs and unsafe PyYAML loaders. It handles assignments,
aliases, multiline calls, and basic control-flow joins through a shared AST taint
engine. It does not follow values across function boundaries or verify that
serialized bytes are authenticated.
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


RULE_ID = "PY015_UNSAFE_DESERIALIZATION_FLOW"
SEVERITY = "high"
MESSAGE = "untrusted data reaches unsafe deserialization"
REMEDIATION = (
    "Prefer data-only formats; never deserialize untrusted pickle-like bytes. "
    "Use yaml.safe_load() for untrusted YAML and authenticate serialized data before loading it."
)
_PICKLE_LOADERS = {
    "pickle.load", "pickle.loads", "dill.load", "dill.loads",
    "cloudpickle.load", "cloudpickle.loads", "joblib.load",
}
_YAML_ALWAYS_UNSAFE = {
    "yaml.unsafe_load", "yaml.unsafe_load_all", "yaml.full_load", "yaml.full_load_all",
}
_YAML_LOADER_CALLS = {"yaml.load", "yaml.load_all"}
_SAFE_YAML_LOADERS = {"yaml.SafeLoader", "yaml.CSafeLoader"}


class _DeserializationAnalyzer(_Analyzer):
    def _unsafe_yaml_loader(self, call: ast.Call, name: str) -> bool:
        if name in _YAML_ALWAYS_UNSAFE:
            return True
        if name not in _YAML_LOADER_CALLS:
            return False
        loader = next((
            keyword.value for keyword in call.keywords if keyword.arg == "Loader"
        ), call.args[1] if len(call.args) > 1 else None)
        if loader is None:
            # PyYAML's default loader has varied by version; require an explicit safe loader.
            return True
        return self._canonical_name(loader) not in _SAFE_YAML_LOADERS

    def _sink(self, call: ast.Call) -> str | None:
        name = self._canonical_name(call.func)
        if name in _PICKLE_LOADERS:
            return name
        if name and self._unsafe_yaml_loader(call, name):
            return name
        if (
            isinstance(call.func, ast.Attribute)
            and call.func.attr == "load"
            and isinstance(call.func.value, ast.Call)
            and self._canonical_name(call.func.value.func) in {
                "pickle.Unpickler", "dill.Unpickler", "cloudpickle.Unpickler",
            }
        ):
            return f"{self._canonical_name(call.func.value.func)}.load"
        return None

    def _sink_data(self, call: ast.Call, sink: str) -> ast.AST | None:
        if sink.endswith("Unpickler.load"):
            unpickler = call.func.value
            return unpickler.args[0] if unpickler.args else None
        for keyword in call.keywords:
            if keyword.arg in {"data", "file", "stream", "filename", "path"}:
                return keyword.value
        return call.args[0] if call.args else None

    def _call_sink(self, call: ast.Call, env: dict) -> None:
        sink = self._sink(call)
        if sink is None:
            return
        data = self._sink_data(call, sink)
        origin = self._taint(data, env)
        if origin is not None:
            self.findings.append(_Finding(
                line=getattr(call, "lineno", 1),
                column=getattr(call, "col_offset", 0) + 1,
                source_line=origin.source_line,
                sink=sink,
            ))


def scan_source(source: Any) -> list[dict[str, Any]]:
    """Return untrusted-source-to-unsafe-deserializer flow findings."""
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
        analyzer = _DeserializationAnalyzer(tree)
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
                f"untrusted value from line {finding.source_line} reaches unsafe "
                f"deserialization via {finding.sink}"
            ),
            "remediation": REMEDIATION,
            "line": finding.line,
            "column": finding.column,
        }
        for finding in sorted(unique.values(), key=lambda item: (item.line, item.column, item.sink))
    ]


__all__ = ["MESSAGE", "REMEDIATION", "RULE_ID", "SEVERITY", "scan_source"]
