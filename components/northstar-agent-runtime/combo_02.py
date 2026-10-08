"""Trusted chain, Integrated.

Combines: provenance_tagging + tool_pinning + hop_validation.
Each hop verifies the tool pin, tags provenance, and validates the hop schema before chaining.

What this IS: a per-hop trust pipeline: pin, tag, validate.
What this IS NOT: a distributed consensus protocol.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

#: Module version.
COMBO_02_VERSION = "combo-02.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.combo-02.v1"


class ComboError(Exception):
    """Fail-closed integration error."""


def _load(name: str):
    path = Path(__file__).resolve().parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


pt = _load("provenance_tagging")
tp = _load("tool_pinning")
hv = _load("hop_validation")


class TrustedChain:
    """Pin-verify -> provenance-tag -> hop-validate, per step."""

    def __init__(self, registry: Any, hop_schema: Any, policy: Dict[str, Any]) -> None:
        self._registry = registry
        self._schema = hop_schema
        self._policy = policy

    def step(
        self,
        tool_id: str,
        definition: Dict[str, Any],
        value: Any,
        hop_payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        try:
            self._registry.check_or_raise(tool_id, definition)
        except tp.ToolPinError as exc:
            raise ComboError(f"pin mismatch for {tool_id}") from exc
        tagged = pt.tag_tool_output(value, tool_id)
        try:
            validated = hv.validate_hop(hop_payload, self._schema)
        except hv.HopValidationError as exc:
            raise ComboError(f"hop invalid: {exc}") from exc
        if not pt.check_policy(tool_id, {"value": tagged}, self._policy):
            raise ComboError(f"provenance policy denied {tool_id}")
        return {"tagged": tagged, "hop": validated}

    def chain(self, steps: List[Dict[str, Any]]) -> Any:
        return pt.combine(*[s["tagged"] for s in steps])


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    tree = ast.parse(
        Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__", "ast", "collections", "dataclasses", "hashlib",
        "importlib", "json", "pathlib", "re", "sys", "typing",
    }
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
    registry = tp.ToolRegistry()
    definition = {"name": "read", "version": "1.0"}
    registry.pin("read", definition, pinned_by="test")
    schema = hv.HopSchema("h", frozenset({"path"}), frozenset({"path"}))
    policy = {"read": {"allowed_sources": {"read"}}}
    chain = TrustedChain(registry, schema, policy)
    s1 = chain.step("read", definition, "data", {"path": "/x"})
    s2 = chain.step("read", definition, "more", {"path": "/y"})
    combined = chain.chain([s1, s2])
    assert "read" in set(combined.deps)
    try:
        chain.step("read", {"name": "read", "version": "9.9"}, "x", {"path": "/z"})
    except ComboError:
        pass
    else:
        raise AssertionError("tampered definition should fail")
    assert stdlib_only()
    print("combo-02 OK: pin, tag, validate, chain")



if __name__ == "__main__":
    main()
