"""Provenance output guard, Integrated.

Combines: provenance_tagging + spotlighting + pii_vault.
Tool output is provenance-tagged, spotlight-delimited so the model treats it as data, and PII-masked before release.

What this IS: a safe tool-output return path: tag, delimit, scrub.
What this IS NOT: a filter on what the tool itself may compute.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

#: Module version.
COMBO_09_VERSION = "combo-09.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.combo-09.v1"


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
sp = _load("spotlighting")
pv = _load("pii_vault")


class ProvenanceOutputGuard:
    """Tag -> spotlight -> mask PII."""

    def __init__(self, run_id: str = "run-09") -> None:
        self._vault = pv.Vault()
        self._run_id = run_id

    def guard(
        self,
        tool_id: str,
        value: Any,
        policy: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        tagged = pt.tag_tool_output(value, tool_id)
        marked, nonce = sp.spotlight(str(value))
        masked, tokens = self._vault.mask(marked, self._run_id)
        policy_ok = True
        if policy is not None:
            policy_ok = pt.check_policy(tool_id, {"out": tagged}, policy)
        return {
            "tagged": tagged,
            "marked": marked,
            "nonce": nonce,
            "masked": masked,
            "tokens": tokens,
            "policy_ok": policy_ok,
        }


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
    g = ProvenanceOutputGuard()
    r = g.guard("search", "found contact bob@example.com here")
    assert "bob@example.com" not in r["masked"]
    assert r["nonce"] in r["marked"]
    assert "search" in set(r["tagged"].deps)
    r2 = g.guard(
        "search", "x", {"search": {"allowed_sources": {"search"}}}
    )
    assert r2["policy_ok"] is True
    r3 = g.guard("search", "x", {"other": {"allowed_sources": {"other"}}})
    assert r3["policy_ok"] is False
    assert stdlib_only()
    print("combo-09 OK: tag, delimit, scrub")



if __name__ == "__main__":
    main()
