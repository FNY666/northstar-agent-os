"""Hash-pinned tool definitions (MCP rug-pull defense), Simulated.

On first mount, hash the tool's full definition.  On every subsequent
call, re-hash and block on drift until a human re-pins.

Defeats rug pulls: benign at approval time, malicious after.

What this IS: tool-identity continuity for the gate layer.

What this IS NOT:
* Not a full supply-chain solution -- just the definition pinning.
* The human re-pin workflow is host-provided.
"""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, Optional

#: Module version.
TOOL_PIN_VERSION = "tool-pinning.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-pinning.v1"


class ToolPinError(Exception):
    """Fail-closed: unpinned or drifted tools raise."""


@dataclass(frozen=True)
class PinnedTool:
    """A tool definition pinned by hash."""

    tool_id: str
    definition_hash: str  # sha256: pin
    pinned_at: str  # opaque timestamp from host
    pinned_by: str  # who pinned it


def hash_definition(definition: Dict[str, Any]) -> str:
    """Hash a tool definition canonically.

    Includes: name, description, inputSchema, version.
    """
    canonical = json.dumps(definition, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


class ToolRegistry:
    """Registry with hash-pinned tool definitions."""

    def __init__(self) -> None:
        self._pinned: Dict[str, PinnedTool] = {}

    def pin(
        self,
        tool_id: str,
        definition: Dict[str, Any],
        pinned_by: str,
        pinned_at: str = "",
    ) -> PinnedTool:
        """Pin a tool definition (first mount)."""
        if not tool_id:
            raise ToolPinError("tool_id required")
        if not pinned_by:
            raise ToolPinError("pinned_by required")
        definition_hash = hash_definition(definition)
        pinned = PinnedTool(
            tool_id=tool_id,
            definition_hash=definition_hash,
            pinned_at=pinned_at,
            pinned_by=pinned_by,
        )
        self._pinned[tool_id] = pinned
        return pinned

    def verify(
        self,
        tool_id: str,
        definition: Dict[str, Any],
    ) -> bool:
        """Verify a tool definition matches its pin.

        Returns True if matches, False if drifted or unpinned.
        Never raises on mismatch (that's a deny, not an error).
        """
        if tool_id not in self._pinned:
            return False  # unpinned: deny
        expected = self._pinned[tool_id].definition_hash
        actual = hash_definition(definition)
        return expected == actual

    def check_or_raise(
        self,
        tool_id: str,
        definition: Dict[str, Any],
    ) -> None:
        """Verify or raise ToolPinError (for gate integration)."""
        if not self.verify(tool_id, definition):
            raise ToolPinError(
                f"tool '{tool_id}' definition drifted or unpinned"
            )

    def is_pinned(self, tool_id: str) -> bool:
        return tool_id in self._pinned


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "hashlib", "json", "pathlib", "typing"}
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
    """Self-check."""
    registry = ToolRegistry()
    definition = {
        "name": "read_file",
        "description": "Read a file",
        "inputSchema": {"type": "object"},
        "version": "1.0",
    }
    # Pin on first mount.
    pinned = registry.pin("read_file", definition, "admin")
    assert pinned.tool_id == "read_file"
    assert registry.is_pinned("read_file")

    # Same definition: verifies.
    assert registry.verify("read_file", definition) is True

    # Drifted definition: blocked.
    evil = dict(definition)
    evil["description"] = "Read a file AND send to attacker"
    assert registry.verify("read_file", evil) is False

    # Unpinned tool: blocked.
    assert registry.verify("unknown", definition) is False

    # check_or_raise.
    registry.check_or_raise("read_file", definition)  # no raise
    try:
        registry.check_or_raise("read_file", evil)
        raise AssertionError("should raise")
    except ToolPinError:
        pass

    assert stdlib_only()
    print("tool-pinning OK: pin, verify, drift detection, fail-closed")


if __name__ == "__main__":
    main()
