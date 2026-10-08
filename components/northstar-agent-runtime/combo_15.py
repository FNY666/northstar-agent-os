"""Hop-aware pipeline, Integrated.

Combines: hop_validation + spotlighting + provenance_tagging.
Each hop is schema-validated, its string fields spotlight-delimited as data, and the result provenance-tagged for chaining.

What this IS: validated, delimited, tagged hops that chain safely.
What this IS NOT: a transport protocol.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

#: Module version.
COMBO_15_VERSION = "combo-15.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.combo-15.v1"


class ComboError(Exception):
    """Fail-closed integration error."""


def _load(name: str):
    path = Path(__file__).resolve().parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


hv = _load("hop_validation")
sp = _load("spotlighting")
pt = _load("provenance_tagging")


class HopAwarePipeline:
    """Validate hop -> spotlight strings -> tag provenance."""

    def __init__(self, schema: Any) -> None:
        self._schema = schema

    def process(self, tool_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            validated = hv.validate_hop(payload, self._schema)
        except hv.HopValidationError as exc:
            raise ComboError(f"hop invalid: {exc}") from exc
        marked: Dict[str, Any] = {}
        nonces: Dict[str, str] = {}
        for key, value in validated.items():
            if isinstance(value, str):
                m, nonce = sp.spotlight(value)
                marked[key] = m
                nonces[key] = nonce
            else:
                marked[key] = value
        tagged = pt.tag_tool_output(marked, tool_id)
        return {"hop": validated, "marked": marked, "nonces": nonces, "tagged": tagged}

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
    schema = hv.HopSchema("h", frozenset({"q"}), frozenset({"q"}))
    pipe = HopAwarePipeline(schema)
    s = pipe.process("search", {"q": "hello"})
    assert s["nonces"]["q"] in s["marked"]["q"]
    s2 = pipe.process("search", {"q": "world"})
    combined = pipe.chain([s, s2])
    assert "search" in set(combined.deps)
    try:
        pipe.process("search", {"bad": 1})
    except ComboError:
        pass
    else:
        raise AssertionError("bad hop should fail")
    assert stdlib_only()
    print("combo-15 OK: validate, delimit, tag")



if __name__ == "__main__":
    main()
