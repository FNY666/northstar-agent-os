"""MCP tools/list drift monitoring: snapshot the tool surface, diff it every call.

An MCP server's ``tools/list`` response is *host-reported*: nothing in the
protocol stops a server from answering differently on the second call than
the first — a new tool appears, an existing tool's schema quietly widens,
a description gets rewritten to change what a model selects. The research
record is unambiguous that this surface is live: servers observed changing
behavior between calls, tool-description injection as a selection-layer
attack (ToolHijacker / ToolCommander family), and population-scale supply
chain contamination (~0.33% clearly malicious skills in a ~900k scan).
Admission-time scanning is necessary but not sufficient; the surface must
be re-checked on every use.

This module is the per-call check side of the contract:

* ``snapshot_tools`` pins a ``tools/list`` response into a
  ``McpToolSnapshot``: one digest-pinned ``ToolPin`` per tool (name,
  description hash, input-schema hash, version). The pin covers exactly
  what a drift would change, and nothing else.
* ``detect_drift`` diffs two snapshots and returns a list of ``ToolDrift``
  records with a fixed ``DriftType`` vocabulary: ``ADDED``, ``REMOVED``,
  ``SCHEMA_CHANGED``, ``DESCRIPTION_CHANGED``. An empty list means the
  surface is unchanged.
* ``assess_drift`` applies the fail-closed policy: any drift touching a
  security-sensitive tool (name contains ``exec``, ``shell``, ``file`` or
  ``network`` — the capabilities that exfiltrate, persist or execute)
  returns ``deny``; anything else returns ``allow`` with the drift log.

Honest scope: this detects *that* the surface changed, not *why*. A
version bump that renames a tool on purpose and a supply-chain attack that
swaps a tool look identical here — both are drift, both get flagged, and
the approval layer decides whether the new surface is acceptable. This
module is the detector, not the defense; it runs on host-reported
``tools/list`` responses and assumes the transport is intact.

Everything here is offline and deterministic. No network, no clock reads.
Digests are ``sha256:`` prefixed hex of JCS-canonical bytes.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence


def _canonical_bytes(obj: Any) -> bytes:
    """JCS-canonical bytes for digest input, with a stdlib fallback."""
    try:
        from canonical_json import jcs_canonical_json as _jcs  # type: ignore
    except Exception:  # pragma: no cover - fallback path
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("utf-8")
    return _jcs(obj)


def _sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class DriftType(str, Enum):
    """Fixed vocabulary for what changed between two tool snapshots."""

    ADDED = "added"
    REMOVED = "removed"
    SCHEMA_CHANGED = "schema-changed"
    DESCRIPTION_CHANGED = "description-changed"


@dataclass(frozen=True)
class ToolPin:
    """Digest-pinned record of one tool as advertised by ``tools/list``.

    ``name`` is the tool's identity; ``description_digest`` and
    ``input_schema_digest`` pin the two drift-relevant fields; ``version``
    is the server-advertised version string (empty when absent — the
    version is informational only and never part of a drift decision).
    ``definition_digest`` pins (name, description, schema) together for
    one-comparison equality.
    """

    name: str
    description_digest: str
    input_schema_digest: str
    version: str = ""
    definition_digest: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("tool name must be a non-empty string")
        for label, value in (("description_digest", self.description_digest),
                             ("input_schema_digest", self.input_schema_digest)):
            if not (isinstance(value, str) and value.startswith("sha256:")
                    and len(value) == len("sha256:") + 64):
                raise ValueError(f"{label} must be a sha256: hex digest")

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description_digest": self.description_digest,
            "input_schema_digest": self.input_schema_digest,
            "version": self.version,
            "definition_digest": self.definition_digest,
        }


@dataclass(frozen=True)
class McpToolSnapshot:
    """Immutable snapshot of one ``tools/list`` response.

    ``server`` names the MCP server (identity, not address); ``tools`` is a
    tuple of ``ToolPin`` in the order advertised. ``snapshot_digest`` pins
    the whole surface so two snapshots can be compared in O(1) before the
    per-tool diff.
    """

    server: str
    tools: tuple[ToolPin, ...] = field(default_factory=tuple)
    snapshot_digest: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.server, str) or not self.server:
            raise ValueError("server must be a non-empty string")
        names = [t.name for t in self.tools]
        if len(names) != len(set(names)):
            raise ValueError("snapshot tools must have unique names")
        if self.snapshot_digest and not (
                isinstance(self.snapshot_digest, str)
                and self.snapshot_digest.startswith("sha256:")
                and len(self.snapshot_digest) == len("sha256:") + 64):
            raise ValueError("snapshot_digest must be a sha256: hex digest")

    def tool_names(self) -> tuple[str, ...]:
        return tuple(t.name for t in self.tools)

    def pin_for(self, name: str) -> ToolPin | None:
        for tool in self.tools:
            if tool.name == name:
                return tool
        return None

    def as_dict(self) -> dict[str, Any]:
        return {
            "server": self.server,
            "tools": [t.as_dict() for t in self.tools],
            "snapshot_digest": self.snapshot_digest,
        }


@dataclass(frozen=True)
class ToolDrift:
    """One detected difference between two snapshots."""

    tool: str
    drift_type: DriftType
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "drift_type": self.drift_type.value,
            "detail": self.detail,
        }


def _pin_tool(entry: Mapping[str, Any]) -> ToolPin:
    name = entry.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError("tool entry must carry a non-empty string 'name'")
    description = entry.get("description", "")
    if not isinstance(description, str):
        raise ValueError(f"tool {name!r}: 'description' must be a string")
    input_schema = entry.get("inputSchema", entry.get("input_schema", {}))
    if not isinstance(input_schema, Mapping):
        raise ValueError(f"tool {name!r}: input schema must be a mapping")
    version = entry.get("version", "")
    if not isinstance(version, str):
        raise ValueError(f"tool {name!r}: 'version' must be a string")

    description_digest = _sha256_hex(_canonical_bytes(description))
    input_schema_digest = _sha256_hex(_canonical_bytes(dict(input_schema)))
    definition_digest = _sha256_hex(_canonical_bytes({
        "name": name,
        "description": description,
        "input_schema": dict(input_schema),
    }))
    return ToolPin(
        name=name,
        description_digest=description_digest,
        input_schema_digest=input_schema_digest,
        version=version,
        definition_digest=definition_digest,
    )


def snapshot_tools(server: str, tools_list: Sequence[Mapping[str, Any]]) -> McpToolSnapshot:
    """Pin a ``tools/list`` response into an immutable snapshot.

    Raises ``ValueError`` on malformed entries (missing name, non-mapping
    schema) and on duplicate tool names — a malformed surface is not a
    surface we can monitor, so fail here instead of silently.
    """
    if not isinstance(server, str) or not server:
        raise ValueError("server must be a non-empty string")
    pins = tuple(_pin_tool(entry) for entry in tools_list)
    names = [p.name for p in pins]
    if len(names) != len(set(names)):
        raise ValueError("tools/list contains duplicate tool names")
    snapshot_digest = _sha256_hex(_canonical_bytes({
        "server": server,
        "tools": sorted(p.definition_digest for p in pins),
    }))
    return McpToolSnapshot(server=server, tools=pins, snapshot_digest=snapshot_digest)


def detect_drift(old: McpToolSnapshot, new: McpToolSnapshot) -> tuple[ToolDrift, ...]:
    """Diff two snapshots; empty tuple means the surface is unchanged.

    Comparison is by name first, then by digest: a tool present in both
    with a changed schema digest is ``SCHEMA_CHANGED``; a changed
    description digest (with unchanged schema) is ``DESCRIPTION_CHANGED``;
    a tool in only one snapshot is ``ADDED`` or ``REMOVED``. If both change
    at once, the schema change is reported (the security-relevant one).
    Snapshots from different servers are not comparable — raises
    ``ValueError``.
    """
    if old.server != new.server:
        raise ValueError(
            f"cannot diff snapshots from different servers: {old.server!r} vs {new.server!r}"
        )
    if old.snapshot_digest and new.snapshot_digest and old.snapshot_digest == new.snapshot_digest:
        return ()

    old_by_name = {t.name: t for t in old.tools}
    new_by_name = {t.name: t for t in new.tools}

    drifts: list[ToolDrift] = []
    for name in old.tool_names():
        if name not in new_by_name:
            drifts.append(ToolDrift(tool=name, drift_type=DriftType.REMOVED,
                                   detail="tool no longer advertised"))
    for name in new.tool_names():
        if name not in old_by_name:
            drifts.append(ToolDrift(tool=name, drift_type=DriftType.ADDED,
                                   detail="new tool advertised"))
        else:
            before, after = old_by_name[name], new_by_name[name]
            if before.input_schema_digest != after.input_schema_digest:
                drifts.append(ToolDrift(tool=name, drift_type=DriftType.SCHEMA_CHANGED,
                                       detail="inputSchema digest changed"))
            elif before.description_digest != after.description_digest:
                drifts.append(ToolDrift(tool=name, drift_type=DriftType.DESCRIPTION_CHANGED,
                                       detail="description digest changed"))
    return tuple(drifts)


#: Substrings that mark a tool as security-sensitive: a drift on one of
#: these fails closed regardless of drift type.
SENSITIVE_TOOL_SUBSTRINGS: tuple[str, ...] = ("exec", "shell", "file", "network")


def is_sensitive_tool(name: str) -> bool:
    """True when the tool name marks security-sensitive capability."""
    lowered = name.lower()
    return any(sub in lowered for sub in SENSITIVE_TOOL_SUBSTRINGS)


@dataclass(frozen=True)
class DriftAssessment:
    """Fail-closed verdict for one drift check."""

    decision: str  # "allow" or "deny"
    drifts: tuple[ToolDrift, ...] = field(default_factory=tuple)
    reason: str = ""

    def __post_init__(self) -> None:
        if self.decision not in ("allow", "deny"):
            raise ValueError("decision must be 'allow' or 'deny'")

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "drifts": [d.as_dict() for d in self.drifts],
            "reason": self.reason,
        }


def assess_drift(drifts: Sequence[ToolDrift]) -> DriftAssessment:
    """Apply the fail-closed policy to a drift list.

    No drift → allow. Any drift on a security-sensitive tool
    (``exec`` / ``shell`` / ``file`` / ``network`` in the name) → deny.
    Other drifts → allow, with the full drift list carried for the audit
    trail. The assessment itself never raises on well-formed input.
    """
    drifts = tuple(drifts)
    if not drifts:
        return DriftAssessment(decision="allow", drifts=(), reason="no drift")
    sensitive = [d for d in drifts if is_sensitive_tool(d.tool)]
    if sensitive:
        names = ", ".join(sorted({d.tool for d in sensitive}))
        return DriftAssessment(
            decision="deny",
            drifts=drifts,
            reason=f"drift on security-sensitive tool(s): {names}",
        )
    return DriftAssessment(
        decision="allow",
        drifts=drifts,
        reason=f"{len(drifts)} non-sensitive drift(s) logged",
    )


def check_tools_list(server: str, baseline: McpToolSnapshot,
                     tools_list: Sequence[Mapping[str, Any]]) -> DriftAssessment:
    """One-call convenience: snapshot the response, diff, assess.

    The intended call site is every ``tools/list`` (or every tool call
    that re-fetches the surface): keep the baseline from admission, call
    this on each response, and treat ``deny`` as a hard stop.
    """
    current = snapshot_tools(server, tools_list)
    drifts = detect_drift(baseline, current)
    return assess_drift(drifts)


def main() -> None:
    tools = [
        {"name": "read_file", "description": "Read a file",
         "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
        {"name": "search", "description": "Search the web",
         "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}},
    ]
    baseline = snapshot_tools("demo-server", tools)
    print(f"baseline: {len(baseline.tools)} tools, digest {baseline.snapshot_digest[:19]}...")
    print("no-drift check:", check_tools_list("demo-server", baseline, tools).decision)
    drifted = [
        {"name": "read_file", "description": "Read a file",
         "inputSchema": {"type": "object",
                         "properties": {"path": {"type": "string"}, "mode": {"type": "string"}}}},
        {"name": "search", "description": "Search the web",
         "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}},
    ]
    assessment = check_tools_list("demo-server", baseline, drifted)
    print(f"drifted check: {assessment.decision} ({assessment.reason})")


if __name__ == "__main__":
    main()
