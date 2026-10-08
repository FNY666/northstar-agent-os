"""Per-value provenance tagging (CaMeL-inspired), Simulated.

Every value carries a capability tag: (readers, provenance).  Provenance
sources: "user" (trusted literals), "internal" (system transforms), or
the tool ID that produced the value.  When values combine, capabilities
union -- readers become the intersection.

Before any tool executes, the policy inspects the arguments AND their
entire dependency closure.  This kills ambient trust: the gate
distinguishes "email from user" from "email extracted from compromised
document."

CaMeL result: 0 of 949 AgentDojo attacks succeeded.

What this IS: the data/instruction separation primitive Northstar was
missing.  Maps directly onto permission-gate argument inspection.

What this IS NOT:
* Not a full taint tracker -- no implicit flow (conditionals) tracking.
  That's STRICT mode, future work.
* Not automatic -- the host must tag values at trust boundaries.
  Untagged values are treated as untrusted (fail-closed).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Optional, Set

#: Module version.
PROVENANCE_VERSION = "provenance-tagging.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.provenance-tagging.v1"

#: Trusted provenance sources.
USER_SOURCE = "user"
INTERNAL_SOURCE = "internal"

#: Readers: public singleton.
PUBLIC_READERS = frozenset({"public"})


class ProvenanceError(Exception):
    """Fail-closed: malformed tags or policy violations raise."""


@dataclass(frozen=True)
class TaggedValue:
    """A value with its capability tag.

    ``readers``: who may see this value (frozenset of principals, or
    PUBLIC_READERS for public data).
    ``provenance``: where it came from -- USER_SOURCE, INTERNAL_SOURCE,
    or a tool ID string.
    ``deps``: frozenset of provenance sources in the dependency closure
    (transitive).  Computed at combine time.
    """

    value: Any
    readers: FrozenSet[str] = PUBLIC_READERS
    provenance: str = INTERNAL_SOURCE
    deps: FrozenSet[str] = frozenset()

    def __post_init__(self):
        if not isinstance(self.provenance, str) or not self.provenance:
            raise ProvenanceError("provenance must be non-empty str")
        # Deps always include own provenance.
        if self.provenance not in self.deps:
            object.__setattr__(
                self, "deps", self.deps | frozenset({self.provenance})
            )


def tag_user(value: Any, readers: Optional[FrozenSet[str]] = None) -> TaggedValue:
    """Tag a user-provided (trusted) value."""
    return TaggedValue(
        value=value,
        readers=readers if readers is not None else PUBLIC_READERS,
        provenance=USER_SOURCE,
    )


def tag_tool_output(
    value: Any, tool_id: str, readers: Optional[FrozenSet[str]] = None
) -> TaggedValue:
    """Tag a tool's output with the tool's ID as provenance."""
    if not tool_id:
        raise ProvenanceError("tool_id required")
    return TaggedValue(
        value=value,
        readers=readers if readers is not None else PUBLIC_READERS,
        provenance=tool_id,
    )


def combine(*tagged: TaggedValue) -> TaggedValue:
    """Combine values: readers intersect, provenance unions.

    The combined value is only as trustworthy as its least-trusted input.
    Returns a TaggedValue wrapping the tuple of input values.
    """
    if not tagged:
        raise ProvenanceError("combine requires at least one value")
    readers = tagged[0].readers
    deps: Set[str] = set()
    for t in tagged:
        readers = readers & t.readers
        deps |= set(t.deps)
    # Combine the raw values into a tuple.
    combined_value = tuple(t.value for t in tagged)
    return TaggedValue(
        value=combined_value,
        readers=readers,
        provenance="combined",
        deps=frozenset(deps),
    )


def check_policy(
    tool_name: str,
    args: Dict[str, TaggedValue],
    policy: Dict[str, Any],
) -> bool:
    """Check if a tool call is allowed given tagged arguments.

    ``policy`` maps tool names to allowed provenance sources, e.g.:
        {"send_email": {"allowed_sources": {"user", "internal"}}}

    A tool call is allowed iff every argument's dependency closure
    contains only allowed sources.  Untagged (raw) values are rejected.

    Returns True if allowed, False if denied.  Never raises on policy
    mismatch (that's a deny, not an error).
    """
    if tool_name not in policy:
        return False  # unknown tool: deny
    allowed = policy[tool_name].get("allowed_sources", set())
    if isinstance(allowed, (list, tuple)):
        allowed = set(allowed)
    for arg_name, tagged in args.items():
        if not isinstance(tagged, TaggedValue):
            return False  # untagged: deny (fail-closed)
        # Every source in the closure must be allowed.
        if not set(tagged.deps) <= set(allowed):
            return False
    return True


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
    """Self-check."""
    # User input is trusted.
    user_email = tag_user("user@example.com")
    assert user_email.provenance == "user"
    assert "user" in user_email.deps

    # Tool output is tagged with tool ID.
    doc_text = tag_tool_output("compromised content", "read_doc")
    assert doc_text.provenance == "read_doc"

    # Combine: readers intersect, deps union.
    combined = combine(user_email, doc_text)
    assert "user" in combined.deps
    assert "read_doc" in combined.deps

    # Policy: send_email only allows user/internal sources.
    policy = {"send_email": {"allowed_sources": {"user", "internal"}}}
    # Pure user data: allow.
    assert check_policy("send_email", {"to": user_email}, policy) is True
    # Tainted by tool output: deny.
    assert check_policy("send_email", {"body": doc_text}, policy) is False
    assert check_policy("send_email", {"body": combined}, policy) is False
    # Untagged: deny.
    assert check_policy("send_email", {"body": "raw"}, policy) is False  # type: ignore
    # Unknown tool: deny.
    assert check_policy("unknown", {"x": user_email}, policy) is False

    assert stdlib_only()
    print("provenance-tagging OK: tag, combine, policy, fail-closed, stdlib")


if __name__ == "__main__":
    main()
