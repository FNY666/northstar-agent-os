"""OpenShell-style tool allowlist: pre-execution validation + enforcement tracing.

Absorbed from NVIDIA OpenShell (Apache 2.0, NVIDIA/OpenShell), verified
against its actual source — nothing taken on announcement faith:

* ``PolicyDocument`` / ``L7Allow`` (``crates/openshell-policy-schema/src/lib.rs``):
  an authored allowlist document where each tool rule matches the tool name
  (``tool: QueryMatcher`` — ``Glob`` short form or ``Any`` of globs) and
  parameter patterns (``params: Map<String, ParameterMatcher>``). Unknown
  fields are rejected (``#[serde(deny_unknown_fields)]`` everywhere).
* ``McpConfig.versions`` (same file, ``parse_mcp_versions``): an *explicitly
  empty* allowlist is rejected as an authoring mistake
  (``ParseMcpVersionsError::Empty``); an omitted field selects the pinned
  default. This module mirrors that: ``"tools": {}`` is a ``ValueError``.
* Interceptor pipeline (``crates/openshell-gateway-interceptors/src/plan.rs``):
  requests pass through ``Phase::ModifyOperation -> Validate -> PostCommit``;
  ``EnforcementGate.check`` is the ``Validate``-phase analogue — a
  pre-execution decision before the executor runs. ``FailurePolicy`` there is
  ``FailClosed | FailOpen``; the same vocabulary is used here.
* Enforcement tracing (``crates/openshell-ocsf``): every enforcement
  decision is emitted as a structured event carrying the action taken
  (``action``: allowed/denied, ``ApiActivityEvent.action``) and the
  disposition (``ApiActivityEvent.disposition``). ``EnforcementEvent`` is the
  offline analogue: one event per check with ``decision`` and ``reason``.

Honest scope: OpenShell enforces at the sandbox/network boundary of a
container runtime (Landlock, L7 proxy, DPU). This module is the *decision
shape* of that mechanism — deterministic, offline, no containers — wired
into ``ActionGateway.execute`` as its final pre-execution validation.
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass
from typing import Any

#: Maximum enforcement events retained per gateway (append-only, bounded —
#: the same bounded-store discipline as the gateway's idempotency tiers).
ENFORCEMENT_TRACE_MAX = 4096

_ALLOWLIST_VERSION_MIN = 1


def _stringify(value: Any) -> str:
    """Render a parameter value for glob matching.

    Scalars stringify directly; containers use canonical JSON so a dict
    argument matches deterministically regardless of key order.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class ToolRule:
    """One allowlisted tool: parameter name -> list of glob patterns (any-of)."""

    name: str
    params: dict[str, tuple[str, ...]]


@dataclass(frozen=True)
class ToolAllowlist:
    """Parsed allowlist document: version + tool rules."""

    version: int
    tools: dict[str, ToolRule]

    @classmethod
    def from_mapping(cls, value: Any) -> "ToolAllowlist":
        """Parse and strictly validate an allowlist document.

        Mirrors OpenShell's ``deny_unknown_fields``: any unknown key is a
        ``ValueError``. An explicitly empty ``tools`` map is rejected as an
        authoring mistake (OpenShell's ``ParseMcpVersionsError::Empty``).
        """
        if not isinstance(value, dict):
            raise ValueError("tool allowlist must be an object")
        unknown = set(value) - {"version", "tools"}
        if unknown:
            raise ValueError(
                "tool allowlist has unknown fields: " + ", ".join(sorted(unknown))
            )
        version = value.get("version")
        if (
            not isinstance(version, int)
            or isinstance(version, bool)
            or version < _ALLOWLIST_VERSION_MIN
        ):
            raise ValueError("tool allowlist version must be an integer >= 1")
        raw_tools = value.get("tools")
        if not isinstance(raw_tools, dict):
            raise ValueError("tool allowlist 'tools' must be an object")
        if not raw_tools:
            raise ValueError(
                "tool allowlist 'tools' is empty: an explicit empty allowlist "
                "denies everything and is treated as an authoring mistake"
            )
        tools: dict[str, ToolRule] = {}
        for name, raw_rule in raw_tools.items():
            if not isinstance(name, str) or not name:
                raise ValueError("tool allowlist tool name must be a non-empty string")
            if not isinstance(raw_rule, dict):
                raise ValueError(f"tool allowlist rule for {name!r} must be an object")
            rule_unknown = set(raw_rule) - {"params"}
            if rule_unknown:
                raise ValueError(
                    f"tool allowlist rule for {name!r} has unknown fields: "
                    + ", ".join(sorted(rule_unknown))
                )
            raw_params = raw_rule.get("params", {})
            if not isinstance(raw_params, dict):
                raise ValueError(
                    f"tool allowlist rule for {name!r} 'params' must be an object"
                )
            params: dict[str, tuple[str, ...]] = {}
            for param, patterns in raw_params.items():
                if not isinstance(param, str) or not param:
                    raise ValueError(
                        f"tool allowlist rule for {name!r} has an invalid "
                        "parameter name"
                    )
                if not isinstance(patterns, list) or not patterns:
                    raise ValueError(
                        f"tool allowlist rule for {name!r} param {param!r}: "
                        "patterns must be a non-empty list of globs"
                    )
                for pattern in patterns:
                    if not isinstance(pattern, str) or not pattern:
                        raise ValueError(
                            f"tool allowlist rule for {name!r} param {param!r}: "
                            "each pattern must be a non-empty glob string"
                        )
                params[param] = tuple(patterns)
            tools[name] = ToolRule(name=name, params=params)
        return cls(version=version, tools=tools)


@dataclass(frozen=True)
class EnforcementDecision:
    """One pre-execution validation verdict: ``allow`` or ``deny`` + reason."""

    decision: str  # "allow" | "deny"
    reason: str


class EnforcementGate:
    """OpenShell ``Validate``-phase analogue: check tool + args vs allowlist.

    Fail-closed semantics: anything not positively allowlisted is denied —
    unknown tool, unlisted parameter, glob mismatch, or a missing parameter
    that carries a rule. ``failure_policy`` mirrors OpenShell's
    ``FailurePolicy``: it only matters when the gate itself errors (it is
    otherwise total); ``fail_open`` then allows with a recorded reason,
    ``fail_closed`` denies.
    """

    def __init__(
        self, allowlist: ToolAllowlist, *, failure_policy: str = "fail_closed"
    ) -> None:
        if not isinstance(allowlist, ToolAllowlist):
            raise ValueError("allowlist must be a ToolAllowlist")
        if failure_policy not in ("fail_closed", "fail_open"):
            raise ValueError("failure_policy must be 'fail_closed' or 'fail_open'")
        self._allowlist = allowlist
        self._failure_policy = failure_policy

    @property
    def allowlist(self) -> ToolAllowlist:
        return self._allowlist

    @property
    def failure_policy(self) -> str:
        return self._failure_policy

    def check(self, tool_name: str, arguments: dict[str, Any]) -> EnforcementDecision:
        rule = self._allowlist.tools.get(tool_name)
        if rule is None:
            return EnforcementDecision("deny", f"tool {tool_name!r} is not allowlisted")
        if not isinstance(arguments, dict):
            return EnforcementDecision("deny", "tool arguments must be an object")
        for param, value in arguments.items():
            patterns = rule.params.get(param)
            if patterns is None:
                return EnforcementDecision(
                    "deny",
                    f"tool {tool_name!r} param {param!r} is not allowlisted",
                )
            rendered = _stringify(value)
            if not any(fnmatch.fnmatchcase(rendered, p) for p in patterns):
                return EnforcementDecision(
                    "deny",
                    f"tool {tool_name!r} param {param!r} value does not match "
                    "any allowlisted pattern",
                )
        for param in rule.params:
            if param not in arguments:
                return EnforcementDecision(
                    "deny",
                    f"tool {tool_name!r} is missing allowlisted param {param!r}",
                )
        return EnforcementDecision(
            "allow",
            f"tool {tool_name!r} matches allowlist v{self._allowlist.version}",
        )


def make_enforcement_event(
    *,
    seq: int,
    tool_name: str,
    arguments_digest: str,
    decision: EnforcementDecision,
    allowlist_version: int,
    failure_policy: str,
) -> dict[str, Any]:
    """Build one enforcement trace event (OCSF action/disposition analogue).

    ``decision.decision`` is the ``action`` (allowed/denied);
    ``decision.reason`` is the ``disposition`` detail.
    """
    return {
        "seq": seq,
        "tool_name": tool_name,
        "arguments_digest": arguments_digest,
        "decision": decision.decision,
        "reason": decision.reason,
        "allowlist_version": allowlist_version,
        "failure_policy": failure_policy,
    }


__all__ = [
    "ENFORCEMENT_TRACE_MAX",
    "EnforcementDecision",
    "EnforcementGate",
    "ToolAllowlist",
    "ToolRule",
    "make_enforcement_event",
]
