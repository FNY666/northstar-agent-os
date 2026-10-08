"""DX-17: Diagnostics (mock), Simulated.

Publish compiler/linter diagnostics per file with severity and line.
`get(file)` returns diagnostics sorted by line then severity rank;
`clear(file)` drops them and returns the removed count. Unknown
severity is rejected at publish time.

What this IS: an explicit per-file diagnostic store.
What this IS NOT: not a real diagnostic engine.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Dict, List

#: Module version.
DX17_DIAGNOSTICS_VERSION = "dx-diagnostics.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.dx-diagnostics.v1"

#: Known severities.
KNOWN_SEVERITIES = frozenset({"error", "warning", "info", "hint"})

#: Sort rank: errors first.
_SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2, "hint": 3}


class DiagnosticsError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class Diagnostic:
    file: str
    line: int
    severity: str
    message: str
    code: str = ""


class DiagnosticStore:
    """Per-file diagnostic store."""

    def __init__(self) -> None:
        self._store: Dict[str, List[Diagnostic]] = {}

    def publish(self, diag: Diagnostic) -> None:
        if not diag.file:
            raise DiagnosticsError("file required")
        if diag.line < 1:
            raise DiagnosticsError("line must be >= 1")
        if diag.severity not in KNOWN_SEVERITIES:
            raise DiagnosticsError(f"unknown severity '{diag.severity}'")
        if not diag.message:
            raise DiagnosticsError("message required")
        self._store.setdefault(diag.file, []).append(diag)

    def get(self, file: str) -> List[Diagnostic]:
        if not file:
            raise DiagnosticsError("file required")
        return sorted(
            self._store.get(file, []),
            key=lambda d: (d.line, _SEVERITY_ORDER[d.severity]),
        )

    def clear(self, file: str) -> int:
        if not file:
            raise DiagnosticsError("file required")
        removed = len(self._store.get(file, []))
        self._store.pop(file, None)
        return removed

    def error_count(self, file: str) -> int:
        return sum(1 for d in self.get(file) if d.severity == "error")

    @property
    def files(self) -> List[str]:
        return sorted(self._store)


def stdlib_only() -> bool:
    import pathlib

    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    store = DiagnosticStore()
    store.publish(Diagnostic("a.py", 5, "warning", "unused var", "W1"))
    store.publish(Diagnostic("a.py", 5, "error", "syntax", "E1"))
    store.publish(Diagnostic("a.py", 2, "info", "note", "I1"))
    diags = store.get("a.py")
    assert [(d.line, d.severity) for d in diags] == [
        (2, "info"), (5, "error"), (5, "warning")
    ]
    assert store.error_count("a.py") == 1
    assert store.get("b.py") == []
    try:
        store.publish(Diagnostic("a.py", 1, "fatal", "x"))
        raise AssertionError("should raise")
    except DiagnosticsError:
        pass
    assert store.clear("a.py") == 3
    assert store.get("a.py") == []
    assert stdlib_only()
    print("dx_17 OK: publish, sorted get, clear, severity validation")


if __name__ == "__main__":
    main()
