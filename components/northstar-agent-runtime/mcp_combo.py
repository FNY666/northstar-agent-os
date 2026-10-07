"""MCP tools/list drift check: hash tripwire + semantic classification.

Combines the two MCP drift methods into one two-stage gate, following the
recommended composition from the method comparison:

1. **Hash tripwire** (``mcp_drift_monitor``): digest the whole surface and
   compare against the admission baseline. One digest comparison covers
   names, descriptions, and schemas in O(1) when nothing changed. A digest
   mismatch tells you *that* something changed, not *what*.
2. **Semantic classification** (``mcp_semantic_diff``): on mismatch, parse
   the JSON Schemas field by field and classify each change as breaking or
   non-breaking, so a vendor's doc fix doesn't halt production while a
   real schema attack still does.

Verdict vocabulary (fixed, fail-closed order):

* ``no_change`` — snapshot digests match; the surface is unchanged.
* ``non_breaking`` — the surface changed, but every change is
  non-breaking (description rewrites on non-sensitive tools, added
  optional fields, widened types, loosened constraints).
* ``breaking_allow_log`` — the surface changed in a breaking way, but on
  a non-sensitive tool (added/removed tool, removed required field,
  narrowed type). Allowed, with the full change list carried for the
  audit/approval layer.
* ``breaking_deny`` — deny: any field-removed on any tool; any
  type-narrowed or constraint-tightened change on a sensitive tool;
  any description change on a sensitive tool (the ToolHijacker family:
  a description rewrite is semantically schema-identical but can inject
  a prompt); any schema change on a sensitive tool that cannot be
  semantically classified because the raw baseline schema is missing
  (fail closed — a mismatch we cannot explain is a deny).

Precedence: ``breaking_deny`` > ``breaking_allow_log`` > ``non_breaking``
> ``no_change``. One deny anywhere denies the whole check.

The raw baseline tools list (``baseline_raw``) is needed to classify
schema changes semantically: snapshots pin digests, not raw schemas.
Without it, schema changes on sensitive tools fail closed and schema
changes on non-sensitive tools are logged as breaking-but-unclassified.
Pass the admission-time ``tools/list`` response alongside the baseline
snapshot to get the full classification.

Honest scope: this is a surface-integrity gate, not a defense against a
lying transport — it assumes the ``tools/list`` response it reads is the
server's actual response. Description-level prompt injection is flagged
for review but not parsed (hash catches it, semantic-diff on schemas
alone does not). Neither stage stops a hostile operator with write
access from re-baselining.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from mcp_drift_monitor import (
    DriftType,
    McpToolSnapshot,
    ToolDrift,
    detect_drift,
    is_sensitive_tool as _hash_is_sensitive,
    snapshot_tools,
)
from mcp_semantic_diff import (
    SemanticChange,
    SemanticChangeKind,
    assess_semantic_risk,
    semantic_diff,
)

#: Module version pin, stamped on every verdict for auditability.
MCP_COMBO_VERSION = "mcp-combo.v1"

#: Fixed verdict vocabulary, in fail-closed precedence order.
NO_CHANGE = "no_change"
NON_BREAKING = "non_breaking"
BREAKING_ALLOW_LOG = "breaking_allow_log"
BREAKING_DENY = "breaking_deny"

_VERDICTS = (NO_CHANGE, NON_BREAKING, BREAKING_ALLOW_LOG, BREAKING_DENY)


@dataclass(frozen=True)
class ComboVerdict:
    """Verdict of the two-stage MCP drift gate."""

    verdict: str  # one of the four vocabulary values
    drifts: tuple[dict[str, Any], ...] = ()
    semantic_changes: tuple[tuple[str, dict[str, Any]], ...] = ()
    reason: str = ""
    version: str = MCP_COMBO_VERSION

    def __post_init__(self) -> None:
        if self.verdict not in _VERDICTS:
            raise ValueError(f"verdict must be one of {_VERDICTS}")

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "drifts": list(self.drifts),
            "semantic_changes": [
                {"tool": tool, "changes": list(changes)}
                for tool, changes in self.semantic_changes
            ],
            "reason": self.reason,
            "version": self.version,
        }


def _raw_schema(entry: Mapping[str, Any]) -> Any:
    """Extract the raw input schema from a tools/list entry."""
    return entry.get("inputSchema", entry.get("input_schema", {}))


def _semantic_for_tool(
    tool: str,
    old_schema: Any,
    new_schema: Any,
) -> tuple[SemanticChange, ...]:
    """Run the semantic diff for one tool's schema pair."""
    return tuple(semantic_diff(old_schema, new_schema))


def check_tools_list(
    server: str,
    baseline: McpToolSnapshot,
    new_list: Sequence[Mapping[str, Any]],
    baseline_raw: Sequence[Mapping[str, Any]] | None = None,
) -> ComboVerdict:
    """Two-stage MCP drift gate: hash tripwire, then semantic classification.

    ``server`` identifies the MCP server; ``baseline`` is the admission-time
    snapshot; ``new_list`` is the fresh ``tools/list`` response;
    ``baseline_raw`` is the admission-time raw response (optional but
    recommended — without it, schema changes cannot be semantically
    classified and fail closed on sensitive tools).

    Malformed ``new_list`` entries raise ``ValueError`` (fail closed at the
    call site — never silently monitor a broken surface).
    """
    if not isinstance(server, str) or not server:
        raise ValueError("server must be a non-empty string")
    if baseline_raw is not None and not isinstance(
        baseline_raw, (list, tuple)
    ):
        raise ValueError("baseline_raw must be a sequence or None")

    current = snapshot_tools(server, new_list)
    drifts = detect_drift(baseline, current)
    if not drifts:
        return ComboVerdict(
            verdict=NO_CHANGE,
            drifts=(),
            semantic_changes=(),
            reason="snapshot digests match; surface unchanged",
        )

    drift_dicts = tuple(d.as_dict() for d in drifts)

    old_by_name: dict[str, Any] = {}
    if baseline_raw is not None:
        for entry in baseline_raw:
            if isinstance(entry, Mapping):
                name = entry.get("name")
                if isinstance(name, str) and name:
                    old_by_name[name] = _raw_schema(entry)
    new_by_name: dict[str, Any] = {}
    for entry in new_list:
        name = entry.get("name")
        if isinstance(name, str) and name:
            new_by_name[name] = _raw_schema(entry)

    semantic_by_tool: list[tuple[str, tuple[dict[str, Any], ...]]] = []
    deny_reasons: list[str] = []
    log_reasons: list[str] = []
    non_breaking_notes: list[str] = []

    for drift in drifts:
        tool = drift.tool
        sensitive = _hash_is_sensitive(tool)
        if drift.drift_type is DriftType.ADDED:
            if sensitive:
                deny_reasons.append(
                    f"deny: new sensitive tool advertised '{tool}'"
                )
            else:
                log_reasons.append(f"tool added '{tool}' (non-sensitive)")
        elif drift.drift_type is DriftType.REMOVED:
            if sensitive:
                deny_reasons.append(
                    f"deny: sensitive tool removed '{tool}'"
                )
            else:
                log_reasons.append(f"tool removed '{tool}' (non-sensitive)")
        elif drift.drift_type is DriftType.DESCRIPTION_CHANGED:
            # A description rewrite is semantically schema-identical but can
            # inject a prompt (ToolHijacker family). The hash stage catches
            # it; the semantic stage on schemas alone cannot.
            if sensitive:
                deny_reasons.append(
                    f"deny: description changed on sensitive tool '{tool}' "
                    "(prompt-injection review required)"
                )
            else:
                non_breaking_notes.append(
                    f"description changed '{tool}' (non-sensitive)"
                )
        elif drift.drift_type is DriftType.SCHEMA_CHANGED:
            old_schema = old_by_name.get(tool)
            new_schema = new_by_name.get(tool)
            if old_schema is None or new_schema is None:
                # Cannot classify without the raw baseline schema.
                if sensitive:
                    deny_reasons.append(
                        f"deny: schema changed on sensitive tool '{tool}' "
                        "and baseline schema unavailable for classification"
                    )
                else:
                    log_reasons.append(
                        f"schema changed '{tool}' (non-sensitive, "
                        "unclassified — baseline schema unavailable)"
                    )
                continue
            changes = _semantic_for_tool(tool, old_schema, new_schema)
            semantic_by_tool.append(
                (
                    tool,
                    tuple(
                        {
                            "kind": ch.kind.value,
                            "field": ch.field,
                            "detail": ch.detail,
                            "breaking": ch.breaking,
                        }
                        for ch in changes
                    ),
                )
            )
            assessment = assess_semantic_risk(changes, is_sensitive=sensitive)
            if assessment.verdict == "deny":
                deny_reasons.extend(assessment.reasons)
            elif any(ch.breaking for ch in changes):
                log_reasons.append(
                    f"breaking schema change on non-sensitive tool '{tool}': "
                    + "; ".join(ch.detail for ch in changes if ch.breaking)
                )
            else:
                non_breaking_notes.append(
                    f"non-breaking schema change '{tool}': "
                    + "; ".join(ch.detail for ch in changes)
                    if changes
                    else f"schema digest changed but no semantic change '{tool}'"
                )

    semantic_tuple = tuple(semantic_by_tool)

    if deny_reasons:
        return ComboVerdict(
            verdict=BREAKING_DENY,
            drifts=drift_dicts,
            semantic_changes=semantic_tuple,
            reason="; ".join(deny_reasons),
        )
    if log_reasons:
        return ComboVerdict(
            verdict=BREAKING_ALLOW_LOG,
            drifts=drift_dicts,
            semantic_changes=semantic_tuple,
            reason="; ".join(log_reasons),
        )
    notes = non_breaking_notes or ["non-breaking changes logged"]
    return ComboVerdict(
        verdict=NON_BREAKING,
        drifts=drift_dicts,
        semantic_changes=semantic_tuple,
        reason="; ".join(notes),
    )


def main() -> None:
    tools_v1 = [
        {
            "name": "read_file",
            "description": "Read a file",
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        },
        {
            "name": "list_dir",
            "description": "List a directory",
            "inputSchema": {"type": "object", "properties": {}},
        },
    ]
    baseline = snapshot_tools("demo", tools_v1)

    v = check_tools_list("demo", baseline, tools_v1, baseline_raw=tools_v1)
    print("unchanged:", v.verdict)
    assert v.verdict == NO_CHANGE

    tools_v2 = [
        {
            "name": "read_file",
            "description": "Read a file",
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        },
        {
            "name": "list_dir",
            "description": "List a directory, now better",
            "inputSchema": {"type": "object", "properties": {}},
        },
    ]
    v = check_tools_list("demo", baseline, tools_v2, baseline_raw=tools_v1)
    print("description-only:", v.verdict)
    assert v.verdict == NON_BREAKING

    tools_v3 = [
        {
            "name": "read_file",
            "description": "Read a file",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "minLength": 5}
                },
                "required": ["path"],
            },
        },
        {
            "name": "list_dir",
            "description": "List a directory",
            "inputSchema": {"type": "object", "properties": {}},
        },
    ]
    v = check_tools_list("demo", baseline, tools_v3, baseline_raw=tools_v1)
    print("tightened-sensitive:", v.verdict)
    assert v.verdict == BREAKING_DENY

    print("mcp-combo OK: tripwire + semantic classification wired")


if __name__ == "__main__":
    main()
