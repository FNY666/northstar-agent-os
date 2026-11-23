"""Tool marketplace (mock registry), Simulated.

A Registry tracks tool entries (name, version, description,
capabilities).  ``search`` matches substrings on name/description.
``install`` only marks an entry installed -- no network, no downloads.
Registering a duplicate name+version raises.

What this IS:
* Simulated in-memory registry of tool metadata.

What this IS NOT:
* Not a real package manager -- no network, no downloads, no installs.
* Not a trust boundary -- entries are mock metadata.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

#: Module version.
TOOL_SYSTEM_27_VERSION = "tool-system-27.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-system-27.v1"


class ToolSystem27Error(Exception):
    """Fail-closed."""


class DuplicateVersion(ToolSystem27Error):
    """Raised on duplicate name+version registration."""


class UnknownEntry(ToolSystem27Error):
    """Raised when a name+version entry is not found."""


@dataclass
class ToolEntry:
    """Mock marketplace entry."""

    name: str
    version: str
    description: str
    capabilities: List[str] = field(default_factory=list)
    installed: bool = False


class Registry:
    """Simulated tool marketplace registry."""

    def __init__(self) -> None:
        self._entries: Dict[Tuple[str, str], ToolEntry] = {}

    @staticmethod
    def _key(name: str, version: str) -> Tuple[str, str]:
        return (name, version)

    def register(self, entry: ToolEntry) -> None:
        if not entry.name or not entry.version:
            raise ToolSystem27Error("name and version required")
        key = self._key(entry.name, entry.version)
        if key in self._entries:
            raise DuplicateVersion(
                f"duplicate entry {entry.name} {entry.version}"
            )
        self._entries[key] = ToolEntry(
            name=entry.name,
            version=entry.version,
            description=entry.description,
            capabilities=list(entry.capabilities),
            installed=False,
        )

    def unregister(self, name: str, version: str) -> None:
        key = self._key(name, version)
        if key not in self._entries:
            raise UnknownEntry(f"no entry {name} {version}")
        del self._entries[key]

    def list(self) -> List[ToolEntry]:
        return sorted(
            self._entries.values(), key=lambda e: (e.name, e.version)
        )

    def search(self, query: str) -> List[ToolEntry]:
        """Substring match on name and description (case-insensitive)."""
        q = query.lower()
        return [
            e
            for e in self.list()
            if q in e.name.lower() or q in e.description.lower()
        ]

    def install(self, name: str, version: str) -> ToolEntry:
        """Mark installed (mock -- no network)."""
        key = self._key(name, version)
        if key not in self._entries:
            raise UnknownEntry(f"no entry {name} {version}")
        self._entries[key].installed = True
        return self._entries[key]

    def list_installed(self) -> List[ToolEntry]:
        return [e for e in self.list() if e.installed]


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    reg = Registry()
    reg.register(
        ToolEntry(
            name="search",
            version="1.0",
            description="Web search tool",
            capabilities=["web", "read"],
        )
    )
    reg.register(
        ToolEntry(
            name="search",
            version="2.0",
            description="Web search tool v2",
            capabilities=["web", "read", "images"],
        )
    )
    assert len(reg.list()) == 2
    assert len(reg.search("v2")) == 1
    assert len(reg.search("SEARCH")) == 2
    # Duplicate name+version raises.
    try:
        reg.register(ToolEntry(name="search", version="1.0", description="dup"))
        raise AssertionError("should raise")
    except DuplicateVersion:
        pass
    # Install marks installed, no network.
    reg.install("search", "1.0")
    assert len(reg.list_installed()) == 1
    assert reg.list_installed()[0].version == "1.0"
    # Install unknown raises.
    try:
        reg.install("nope", "9.9")
        raise AssertionError("should raise")
    except UnknownEntry:
        pass
    reg.unregister("search", "2.0")
    assert len(reg.list()) == 1
    assert stdlib_only()
    print("tool_system_27 OK: register, search, install, conflicts")


if __name__ == "__main__":
    main()
