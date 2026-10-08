"""DX-14: Go to definition (mock), Simulated.

Symbol -> single definition location (file, line, column).
`definition(symbol)` raises on unknown symbols (fail-closed) because a
"jump" target must exist; there is no sensible null target.

Index is built explicitly via `index()` calls -- this module never
guesses locations.

What this IS: an explicit definition index.
What this IS NOT: not a real indexer (no parsing).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Dict, List

#: Module version.
DX14_DEFINITION_VERSION = "dx-goto-def.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.dx-goto-def.v1"


class DefinitionError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class Location:
    file: str
    line: int
    column: int = 0


class DefinitionIndex:
    """Explicit symbol -> definition index."""

    def __init__(self) -> None:
        self._index: Dict[str, Location] = {}

    def index(self, symbol: str, location: Location) -> None:
        if not symbol or not symbol.strip():
            raise DefinitionError("symbol required")
        if not location.file:
            raise DefinitionError("location file required")
        if location.line < 1:
            raise DefinitionError("line must be >= 1")
        self._index[symbol] = location

    def definition(self, symbol: str) -> Location:
        """Return the definition location.  Unknown raises."""
        if not isinstance(symbol, str) or not symbol.strip():
            raise DefinitionError("symbol must be non-empty str")
        loc = self._index.get(symbol)
        if loc is None:
            raise DefinitionError(f"no definition for '{symbol}'")
        return loc

    def has(self, symbol: str) -> bool:
        return symbol in self._index

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
    idx = DefinitionIndex()
    idx.index("allow", Location(file="gates.py", line=42, column=4))
    loc = idx.definition("allow")
    assert (loc.file, loc.line, loc.column) == ("gates.py", 42, 4)
    assert idx.has("allow") and not idx.has("deny")
    try:
        idx.definition("deny")
        raise AssertionError("should raise")
    except DefinitionError:
        pass
    try:
        idx.index("x", Location(file="a.py", line=0))
        raise AssertionError("should raise")
    except DefinitionError:
        pass
    assert stdlib_only()
    print("dx_14 OK: index, lookup, unknown raises")


if __name__ == "__main__":
    main()
