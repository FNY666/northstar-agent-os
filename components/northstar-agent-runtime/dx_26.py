"""DX-26: API docs generation (mock), Simulated.

Documented symbol catalog (name, signature, docstring). `render(name,
fmt)` emits markdown or plain text; rendering an undocumented symbol
raises. `undocumented()` lists symbols with empty docstrings.

What this IS: canned doc rendering from an explicit catalog.
What this IS NOT: not extracted from real source.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Dict, List

#: Module version.
DX26_APIDOCS_VERSION = "dx-apidocs.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.dx-apidocs.v1"

#: Known render formats.
KNOWN_FORMATS = frozenset({"markdown", "plain"})


class ApiDocsError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class DocEntry:
    name: str
    signature: str
    doc: str = ""


class DocCatalog:
    """Explicit documented-symbol catalog."""

    def __init__(self) -> None:
        self._docs: Dict[str, DocEntry] = {}

    def document(self, entry: DocEntry) -> None:
        if not entry.name or not entry.name.strip():
            raise ApiDocsError("name required")
        if entry.name in self._docs:
            raise ApiDocsError(f"duplicate doc '{entry.name}'")
        if not entry.signature:
            raise ApiDocsError("signature required")
        self._docs[entry.name] = entry

    def render(self, name: str, fmt: str = "markdown") -> str:
        if name not in self._docs:
            raise ApiDocsError(f"no doc for '{name}'")
        if fmt not in KNOWN_FORMATS:
            raise ApiDocsError(f"unknown format '{fmt}'")
        entry = self._docs[name]
        if not entry.doc:
            raise ApiDocsError(f"'{name}' is undocumented")
        if fmt == "markdown":
            return f"## `{entry.name}{entry.signature}`\n\n{entry.doc}\n"
        return f"{entry.name}{entry.signature}\n{entry.doc}\n"

    def undocumented(self) -> List[str]:
        return sorted(n for n, e in self._docs.items() if not e.doc)

    @property
    def names(self) -> List[str]:
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
    cat = DocCatalog()
    cat.document(DocEntry("allow", "(tool, args)", "Allow a tool call."))
    cat.document(DocEntry("todo", "(x)", ""))
    md = cat.render("allow")
    assert md.startswith("## `allow(tool, args)`")
    assert "Allow a tool call." in md
    plain = cat.render("allow", fmt="plain")
    assert plain.startswith("allow(tool, args)")
    assert cat.undocumented() == ["todo"]
    try:
        cat.render("todo")
        raise AssertionError("should raise")
    except ApiDocsError:
        pass
    try:
        cat.render("nope")
        raise AssertionError("should raise")
    except ApiDocsError:
        pass
    try:
        cat.render("allow", fmt="html")
        raise AssertionError("should raise")
    except ApiDocsError:
        pass
    assert stdlib_only()
    print("dx_26 OK: markdown/plain render, undocumented, validation")


if __name__ == "__main__":
    main()
