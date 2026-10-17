"""Bounded AST taint analysis for Python path-traversal flows.

The scanner follows common request, CLI, environment, and interactive-input
sources into filesystem paths and file APIs. It handles import aliases,
multiline calls, assignments, and bounded direct calls to same-file top-level
helpers. It does not resolve method dispatch or cross-file flows, or prove that
path containment and symlink protections are correct.
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


RULE_ID = "PY012_PATH_TRAVERSAL"
SEVERITY = "high"
MESSAGE = "request-derived value used as a filesystem path"
REMEDIATION = (
    "Map user-facing identifiers to server-owned paths or resolve paths under a trusted root; "
    "enforce containment after symlink resolution and use race-safe file opens."
)
_PATH_METHODS = {
    "open", "read_text", "read_bytes", "write_text", "write_bytes", "unlink", "rmdir",
    "rename", "replace", "mkdir", "touch", "iterdir", "glob", "rglob", "exists",
    "is_file", "is_dir",
}
_FILE_CALL_PATHS: dict[str, tuple[int, ...]] = {
    "open": (0,),
    "builtins.open": (0,),
    "io.open": (0,),
    "aiofiles.open": (0,),
    "os.open": (0,),
    "os.remove": (0,),
    "os.unlink": (0,),
    "os.rmdir": (0,),
    "os.rename": (0, 1),
    "os.replace": (0, 1),
    "os.mkdir": (0,),
    "os.makedirs": (0,),
    "os.listdir": (0,),
    "os.scandir": (0,),
    "shutil.copy": (0, 1),
    "shutil.copyfile": (0, 1),
    "shutil.copy2": (0, 1),
    "shutil.copytree": (0, 1),
    "shutil.move": (0, 1),
    "shutil.rmtree": (0,),
    "send_file": (0,),
    "flask.send_file": (0,),
    "flask.helpers.send_file": (0,),
    "FileResponse": (0,),
    "starlette.responses.FileResponse": (0,),
    "fastapi.responses.FileResponse": (0,),
    "django.http.FileResponse": (0,),
    "django.http.response.FileResponse": (0,),
}
_PATH_KEYWORDS = {
    "file", "filename", "name", "path", "path_or_file", "src", "source", "dst",
    "destination",
}
_RENAME_METHODS = {"rename", "replace"}
_PATH_CONSTRUCTORS = {
    "Path", "pathlib.Path", "pathlib.PurePath", "pathlib.PosixPath", "pathlib.WindowsPath",
}


class _PathAnalyzer(_Analyzer):
    def _path_constructor_argument(self, node: ast.AST) -> ast.AST | None:
        if not isinstance(node, ast.Call):
            return None
        name = self._canonical_name(node.func)
        if name in _PATH_CONSTRUCTORS or (
            isinstance(node.func, ast.Name) and node.func.id == "Path"
        ):
            return node.args[0] if node.args else None
        return None

    def _path_method_data(self, call: ast.Call) -> list[ast.AST]:
        if not isinstance(call.func, ast.Attribute) or call.func.attr not in _PATH_METHODS:
            return []
        receiver = call.func.value
        constructor_argument = self._path_constructor_argument(receiver)
        paths = [constructor_argument or receiver]
        if call.func.attr in _RENAME_METHODS and call.args:
            paths.append(call.args[0])
        for keyword in call.keywords:
            if keyword.arg in _PATH_KEYWORDS:
                paths.append(keyword.value)
        return paths

    def _file_call_data(self, call: ast.Call) -> list[ast.AST]:
        name = self._canonical_name(call.func)
        indices = _FILE_CALL_PATHS.get(name or "")
        # Keep the historical convenience forms where imports were omitted.
        if indices is None and isinstance(call.func, ast.Name):
            indices = _FILE_CALL_PATHS.get(call.func.id)
        if indices is None:
            return []
        paths = [call.args[index] for index in indices if len(call.args) > index]
        paths.extend(
            keyword.value for keyword in call.keywords if keyword.arg in _PATH_KEYWORDS
        )
        return paths

    def _sink_paths(self, call: ast.Call) -> list[ast.AST]:
        file_call_paths = self._file_call_data(call)
        return file_call_paths or self._path_method_data(call)

    def _taint(self, node: ast.AST | None, env: dict):
        if isinstance(node, ast.Call) and self._sink_paths(node):
            # A file operation's result is not an alias of the path it used.
            return None
        return super()._taint(node, env)

    def _call_sink(self, call: ast.Call, env: dict) -> None:
        paths = self._sink_paths(call)
        if not paths:
            return
        origins = [self._taint(path, env) for path in paths]
        origins = [origin for origin in origins if origin is not None]
        if not origins:
            return
        origin = min(origins, key=lambda item: item.source_line)
        self.findings.append(_Finding(
            line=getattr(call, "lineno", 1),
            column=getattr(call, "col_offset", 0) + 1,
            source_line=origin.source_line,
            sink=self._canonical_name(call.func) or ast.unparse(call.func),
        ))


def scan_source(source: Any) -> list[dict[str, Any]]:
    """Return untrusted-source-to-filesystem flow findings."""
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
        analyzer = _PathAnalyzer(tree)
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
                f"untrusted value from line {item.source_line} reaches filesystem API "
                f"via {item.sink}"
            ),
            "remediation": REMEDIATION,
            "line": item.line,
            "column": item.column,
        }
        for item in sorted(unique.values(), key=lambda finding: (finding.line, finding.column, finding.sink))
    ]


__all__ = ["MESSAGE", "REMEDIATION", "RULE_ID", "SEVERITY", "scan_source"]
