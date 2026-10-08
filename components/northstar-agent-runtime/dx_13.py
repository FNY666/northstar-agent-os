"""DX-13: Hover docs (mock), Simulated.

Symbol -> documentation registry.  `hover(symbol)` returns a
HoverDoc (signature + markdown docs) or None when the symbol is
unknown.  Empty symbol raises (fail-closed); unknown symbols return
None rather than fabricated docs.

What this IS: a doc lookup table with a typed result.
What this IS NOT: not a doc extractor (no AST parsing here).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Dict, List, Optional

#: Module version.
DX13_HOVER_VERSION = "dx-hover.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.dx-hover.v1"


class HoverError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class HoverDoc:
    symbol: str
    signature: str
    docs: str
    kind: str = "symbol"


class HoverDocs:
    """Mock hover-documentation registry."""

    def __init__(self) -> None:
        self._docs: Dict[str, HoverDoc] = {}

    def add(self, doc: HoverDoc) -> None:
        if not doc.symbol or not doc.symbol.strip():
            raise HoverError("symbol required")
        self._docs[doc.symbol] = doc

    def hover(self, symbol: str) -> Optional[HoverDoc]:
        """Return docs or None.  Empty symbol raises."""
        if not isinstance(symbol, str):
            raise HoverError("symbol must be str")
        if not symbol.strip():
            raise HoverError("symbol must be non-empty")
        return self._docs.get(symbol)

    def render_markdown(self, symbol: str) -> Optional[str]:
        doc = self.hover(symbol)
        if doc is None:
            return None
        return f"```\n{doc.signature}\n```\n\n{doc.docs}"

    @property
    def symbols(self) -> List[str]:
        return sorted(self._docs)


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
    h = HoverDocs()
    h.add(HoverDoc(symbol="allow", signature="allow(tool, args) -> bool",
                   docs="Returns True when the gate allows the action."))
    doc = h.hover("allow")
    assert doc is not None and "gate allows" in doc.docs
    md = h.render_markdown("allow")
    assert md is not None and "allow(tool, args)" in md
    assert h.hover("unknown_symbol") is None  # no fabrication
    assert h.render_markdown("unknown_symbol") is None
    try:
        h.hover("")
        raise AssertionError("should raise")
    except HoverError:
        pass
    assert stdlib_only()
    print("dx_13 OK: lookup, markdown render, unknown->None")


if __name__ == "__main__":
    main()
