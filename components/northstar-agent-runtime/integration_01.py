"""Integration I-001: provenance + spotlighting (tag then spotlight), Simulated.

One call that (1) tags untrusted tool output with its provenance via
provenance_tagging.tag_tool_output, then (2) marks the data/instruction
boundary with spotlighting.spotlight.  The tagged value keeps raw data for
policy checks; the spotlighted string is what enters the model context.

What this IS: tag-and-mark for tool results.
What this IS NOT: not a policy decider -- provenance.check_policy still decides.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, FrozenSet, Optional

#: Module version.
INTEGRATION_01_VERSION = "integration-01.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.integration-01.v1"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).resolve().parent / f"{name}.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_provenance = _load("provenance_tagging")
_spotlight = _load("spotlighting")


class IntegrationError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class TaggedSpotlightResult:
    """Tool output tagged with provenance and marked for the model."""

    tagged: Any  # provenance_tagging.TaggedValue
    marked: str
    nonce: str
    tool_id: str


class ProvenanceSpotlight:
    """Tags tool output, then spotlights it."""

    def __init__(self, *, level: str = "delimit") -> None:
        if level not in ("delimit", "datamark", "base64"):
            raise IntegrationError(f"unknown level {level!r}")
        self._level = level

    def process(
        self,
        tool_id: str,
        data: str,
        readers: Optional[FrozenSet[str]] = None,
    ) -> TaggedSpotlightResult:
        """Tag with provenance, then spotlight.  Returns both."""
        if not tool_id:
            raise IntegrationError("tool_id required")
        if not isinstance(data, str):
            raise IntegrationError("data must be str")
        tagged = _provenance.tag_tool_output(data, tool_id, readers)
        marked, nonce = _spotlight.spotlight(data, level=self._level)
        return TaggedSpotlightResult(
            tagged=tagged, marked=marked, nonce=nonce, tool_id=tool_id
        )

    def check_policy(
        self,
        tool_name: str,
        args: Dict[str, Any],
        policy: Dict[str, Any],
    ) -> bool:
        """Provenance policy check on tagged args."""
        return _provenance.check_policy(tool_name, args, policy)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    tree = ast.parse(
        Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__", "ast", "dataclasses", "importlib", "pathlib", "sys",
        "typing",
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
    """Self-check."""
    ps = ProvenanceSpotlight()
    r = ps.process("read_doc", "hello <script>")
    assert r.tagged.provenance == "read_doc"
    assert f"nonce={r.nonce}" in r.marked
    assert "hello <script>" in r.marked

    # base64 hides plaintext from the model context.
    ps64 = ProvenanceSpotlight(level="base64")
    r64 = ps64.process("fetch", "secret")
    assert "secret" not in r64.marked

    # Policy: tainted value denied for send_email; user value allowed.
    policy = {"send_email": {"allowed_sources": {"user", "internal"}}}
    assert ps.check_policy("send_email", {"body": r.tagged}, policy) is False
    assert (
        ps.check_policy(
            "send_email", {"body": _provenance.tag_user("hi")}, policy
        )
        is True
    )

    assert stdlib_only()
    print("integration-01 OK: tag then spotlight, policy, stdlib")


if __name__ == "__main__":
    main()
