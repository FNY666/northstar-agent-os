"""DX-15: Find references (mock), Simulated.

Symbol -> list of reference locations (file, line).  `references(symbol)`
raises on unknown symbols (fail-closed); an empty result is only
returned for symbols that were explicitly indexed with zero references.

What this IS: an explicit reference index.
What this IS NOT: not a real reference finder.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Dict, List

#: Module version.
DX15_REFERENCES_VERSION = "dx-find-refs.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.dx-find-refs.v1"


class ReferencesError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class RefLocation:
    file: str
    line: int
    column: int = 0


class ReferenceIndex:
    """Explicit symbol -> references index."""

    def __init__(self) -> None:
        self._index: Dict[str, List[RefLocation]] = {}

    def index(self, symbol: str, refs: List[RefLocation]) -> None:
        if not symbol or not symbol.strip():
            raise ReferencesError("symbol required")
        for r in refs:
            if not r.file:
                raise ReferencesError("ref file required")
            if r.line < 1:
                raise ReferencesError("ref line must be >= 1")
        # dedupe, keep order
        seen = set()
        uniq: List[RefLocation] = []
        for r in refs:
            key = (r.file, r.line, r.column)
            if key not in seen:
                seen.add(key)
                uniq.append(r)
        self._index[symbol] = uniq

    def references(self, symbol: str) -> List[RefLocation]:
        """Return reference locations.  Unknown symbol raises."""
        if not isinstance(symbol, str) or not symbol.strip():
            raise ReferencesError("symbol must be non-empty str")
        if symbol not in self._index:
            raise ReferencesError(f"no references indexed for '{symbol}'")
        return list(self._index[symbol])

    def count(self, symbol: str) -> int:
        return len(self.references(symbol))

    @property
    def symbols(self) -> List[str]:
        return sorted(self._index)


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
    idx = ReferenceIndex()
    idx.index("allow", [
        RefLocation("a.py", 10), RefLocation("b.py", 3),
        RefLocation("a.py", 10),  # duplicate dropped
    ])
    refs = idx.references("allow")
    assert len(refs) == 2
    assert idx.count("allow") == 2
    idx.index("unused", [])
    assert idx.references("unused") == []
    try:
        idx.references("nope")
        raise AssertionError("should raise")
    except ReferencesError:
        pass
    assert stdlib_only()
    print("dx_15 OK: index, dedupe, unknown raises")


if __name__ == "__main__":
    main()
