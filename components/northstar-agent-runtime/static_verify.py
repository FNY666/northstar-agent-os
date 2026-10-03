"""Static pre-dispatch verification of tool-call policies (ninety-first batch).

Absorbed from **Agentic-AI-Risk-Mitigation/Janus** ("System-level security
for LLM agents: fine-grained policy enforcement on tool calls"), read as
*code*, not docs — the files actually studied, in ``/tmp/janus-src``:

* ``janus/policy/enforcer.py`` — ``PolicyEnforcer.enforce``: priority-ordered
  ``(priority, effect, conditions, fallback)`` rules per tool; allow rules
  (effect=0) match only when ALL conditions pass; **strict mode** (default):
  an allow rule whose condition names an argument absent from the call does
  NOT match — "a caller can bypass a restriction by omitting the argument";
  deny rules (effect=1) match vacuously on absent args (fail closed); no
  rule matches → default deny. ``_sort_policy`` sorts deny before allow at
  equal priority (fail-closed tie-break).
* ``janus/policy/validator.py`` — ``validate_argument``: three restriction
  kinds — ``dict`` = JSON Schema (via the ``jsonschema`` library), ``str`` =
  regex, ``callable`` = custom validator; a context-aware condition evaluated
  without its ``ConditionContext`` fails closed ("deny, never guess").
* ``janus/policy/loader.py`` — ``validate_policy_structure``: *static*
  cross-validation of a policy against tool definitions — every policy tool
  name must exist; every condition argument must exist in the tool's schema;
  every condition schema must be valid JSON Schema. Returns warnings; this
  module turns violations into hard errors (fail closed).
* ``janus/tools/registry.py`` — ``ToolRegistry.register`` **overwrites any
  existing registration with the same name, silently**. There is no hash or
  signature pinning of tool definitions: whoever can re-register a tool can
  swap its handler, its schema, or its description without any check
  firing. That is the gap this module closes.

Northstar mapping (honest scope):

* Janus's enforcement is *runtime* (``enforce()`` runs on the live call);
  what is absorbed here is the **static** half of its design — policy
  verified against pinned tool definitions **before dispatch**, so a
  violation is denied without any tool code, handler, or side effect
  ever being reached. Cheaper than runtime interception, and immune to
  anything that happens at execution time.
* The digest-pinned ``DefinitionRegistry`` is what Janus's registry
  lacks: a definition is registered once and its canonical digest pinned;
  any re-registration whose digest differs is a **definition-tamper**
  event and fail-closes every subsequent call for that tool. Silent
  overwrite is never permitted.
* Argument restriction checking is a stdlib-only subset (type, pattern,
  enum, minimum/maximum, minLength/maxLength) — honestly *not* full JSON
  Schema the way Janus's ``jsonschema``-backed validator is. The module
  docstring and each restriction say exactly which subset is enforced;
  anything outside the subset is rejected at policy-build time rather
  than silently ignored.
* Caller capabilities are checked statically: every tool declares the
  capability set it requires, and the caller's (name, args-shape,
  caller-caps) triple is verified as a whole. A call from a caller that
  does not hold the tool's required capabilities is denied before
  dispatch — the same class of check as the passport/capability work in
  the eighty-ninth batch, applied at the pre-dispatch seam.

Fail-closed rules (non-negotiable):

1. Unknown tool → deny.
2. Definition digest mismatch (tampered re-registration) → deny + tamper
   event. Never silent overwrite.
3. Argument not in the pinned schema → deny (arg smuggling).
4. Required argument missing or type-mismatched → deny.
5. Caller lacks a required capability → deny.
6. No policy rule matches → deny (Janus default-deny).
7. Malformed policy / restriction outside the enforced subset → the
   policy is refused at build time; there is no "lenient" mode.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Effects and verdicts (Janus vocabulary, ported)
# ---------------------------------------------------------------------------

ALLOW = 0
DENY = 1

_VERDICT_ALLOW = "allow"
_VERDICT_DENY = "deny"

# The enforced subset of JSON-Schema-ish restrictions. Anything else in a
# policy condition is refused at build time (StaticVerifyError), never
# silently ignored.
_KNOWN_RESTRICTION_KEYS = frozenset(
    {"type", "pattern", "enum", "minimum", "maximum", "minLength", "maxLength"}
)

_TYPE_NAMES = frozenset(
    {"string", "integer", "number", "boolean", "array", "object", "null"}
)


class StaticVerifyError(Exception):
    """Raised for malformed policies, definitions, or restriction specs.

    Build-time failures only. Call-time denials are returned as
    ``StaticVerdict`` with ``verdict="deny"`` (deny-before-dispatch), never
    raised — the gate answers, it does not throw.
    """


class DefinitionTamper(Exception):
    """Raised when a re-registration's digest differs from the pinned digest.

    This is the event Janus's ``ToolRegistry.register`` can never produce:
    a silent definition swap. Here it is loud and fail-closed.
    """


# ---------------------------------------------------------------------------
# Canonical digest (the signature Janus's registry lacks)
# ---------------------------------------------------------------------------


def canonical_json(value: Any) -> str:
    """Deterministic JSON encoding for digesting (sorted keys, tight separators)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def definition_digest(definition: dict[str, Any]) -> str:
    """SHA-256 over the canonical form of a tool definition.

    The definition is the (name, description, params) triple — the same
    surface Janus's ``ToolDef`` exposes to policy validation
    (``to_janus_tool_spec``). Handler code is deliberately *not* part of
    the digest: the digest pins the *contract* the policy was verified
    against, not the implementation behind it.
    """
    canonical = {
        "name": definition["name"],
        "description": definition.get("description", ""),
        "params": [
            {
                "name": p["name"],
                "type": p["type"],
                "required": bool(p.get("required", True)),
                "enum": p.get("enum"),
            }
            for p in definition.get("params", [])
        ],
        "required_caps": sorted(definition.get("required_caps", [])),
    }
    return sha256_hex(canonical_json(canonical))


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolParam:
    """One parameter of a tool definition (Janus ``ToolParam`` shape)."""

    name: str
    type: str  # JSON-Schema-ish type name
    required: bool = True
    enum: tuple[Any, ...] | None = None

    def __post_init__(self) -> None:
        if not self.name or not isinstance(self.name, str):
            raise StaticVerifyError("ToolParam.name must be a non-empty string")
        if self.type not in _TYPE_NAMES:
            raise StaticVerifyError(
                f"ToolParam {self.name!r}: unknown type {self.type!r} "
                f"(known: {sorted(_TYPE_NAMES)})"
            )


@dataclass(frozen=True)
class ToolDefinition:
    """A tool's static contract: name, description, params, required caps.

    This is the definition whose digest is pinned at registration. Any
    later change to name/description/params/required_caps changes the
    digest and is therefore a tamper event, not an update.
    """

    name: str
    description: str = ""
    params: tuple[ToolParam, ...] = ()
    required_caps: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not self.name or not isinstance(self.name, str):
            raise StaticVerifyError("ToolDefinition.name must be a non-empty string")
        seen: set[str] = set()
        for p in self.params:
            if p.name in seen:
                raise StaticVerifyError(
                    f"ToolDefinition {self.name!r}: duplicate param {p.name!r}"
                )
            seen.add(p.name)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "params": [
                {
                    "name": p.name,
                    "type": p.type,
                    "required": p.required,
                    "enum": list(p.enum) if p.enum is not None else None,
                }
                for p in self.params
            ],
            "required_caps": sorted(self.required_caps),
        }

    @property
    def digest(self) -> str:
        return definition_digest(self.to_dict())


# ---------------------------------------------------------------------------
# Definition registry with digest pinning
# ---------------------------------------------------------------------------


class DefinitionRegistry:
    """Registers tool definitions with pinned digests.

    The Janus gap, closed: ``register`` never silently overwrites. A
    re-registration with an identical digest is a no-op (idempotent); a
    re-registration with a *different* digest raises ``DefinitionTamper``
    and the tool is marked tampered — every later ``verify_call`` for it
    denies fail-closed until an explicit, audited ``force_reregister``
    replaces the pin (the only path, and it emits a tamper-resolution
    event).
    """

    def __init__(self) -> None:
        self._defs: dict[str, ToolDefinition] = {}
        self._pins: dict[str, str] = {}
        self._tampered: set[str] = set()
        self._events: list[dict[str, Any]] = []

    # -- registration ----------------------------------------------------

    def register(self, definition: ToolDefinition) -> str:
        """Register a definition, pinning its digest. Returns the digest."""
        digest = definition.digest
        existing = self._defs.get(definition.name)
        if existing is None:
            self._defs[definition.name] = definition
            self._pins[definition.name] = digest
            self._emit("static_verify.registered", definition.name, digest, None)
            return digest
        if self._pins[definition.name] == digest:
            # Idempotent re-registration of the identical definition.
            self._emit("static_verify.registered", definition.name, digest, "idempotent")
            return digest
        # Digest differs: tamper. Loud, fail-closed, never silent.
        self._tampered.add(definition.name)
        self._emit(
            "static_verify.definition_tamper",
            definition.name,
            digest,
            f"pinned={self._pins[definition.name][:12]}",
        )
        raise DefinitionTamper(
            f"tool {definition.name!r}: definition digest {digest[:12]}… does not "
            f"match pinned {self._pins[definition.name][:12]}… — refusing silent "
            "overwrite (use force_reregister for an audited replacement)"
        )

    def force_reregister(self, definition: ToolDefinition, *, reason: str) -> str:
        """Audited replacement of a pinned definition. Requires a reason.

        The only path past a tamper flag. Emits a resolution event so the
        replacement is visible in the audit chain.
        """
        if not reason or not reason.strip():
            raise StaticVerifyError("force_reregister requires a non-empty reason")
        digest = definition.digest
        self._defs[definition.name] = definition
        self._pins[definition.name] = digest
        self._tampered.discard(definition.name)
        self._emit("static_verify.reregistered", definition.name, digest, reason)
        return digest

    # -- lookup ----------------------------------------------------------

    def get(self, name: str) -> ToolDefinition | None:
        return self._defs.get(name)

    def pinned_digest(self, name: str) -> str | None:
        return self._pins.get(name)

    def is_tampered(self, name: str) -> bool:
        return name in self._tampered

    def names(self) -> frozenset[str]:
        return frozenset(self._defs)

    def events(self) -> list[dict[str, Any]]:
        return list(self._events)

    def _emit(
        self, kind: str, tool: str, digest: str | None, detail: str | None
    ) -> None:
        self._events.append(
            {"event": kind, "tool": tool, "digest": digest, "detail": detail}
        )


# ---------------------------------------------------------------------------
# Policy rules (Janus rule shape, statically checked)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicyRule:
    """One Janus-style rule: (priority, effect, conditions, fallback).

    conditions: {arg_name: restriction} where restriction is a dict drawn
    from the enforced subset (type/pattern/enum/minimum/maximum/
    minLength/maxLength). fallback is informational here — the static gate
    only ever denies (deny-before-dispatch); fallbacks like "ask user"
    belong to the runtime approval layer (action_card), not to static
    verification.
    """

    priority: int
    effect: int  # ALLOW or DENY
    conditions: dict[str, dict[str, Any]]
    fallback: int = 0

    def __post_init__(self) -> None:
        if self.effect not in (ALLOW, DENY):
            raise StaticVerifyError(f"rule effect must be ALLOW(0)/DENY(1), got {self.effect!r}")
        if not isinstance(self.priority, int):
            raise StaticVerifyError("rule priority must be an int")
        for arg_name, restriction in self.conditions.items():
            _check_restriction(arg_name, restriction)


def _check_restriction(arg_name: str, restriction: Any) -> None:
    """Validate a restriction spec against the enforced subset."""
    if not isinstance(restriction, dict):
        raise StaticVerifyError(
            f"condition on {arg_name!r}: restriction must be a dict from the "
            f"enforced subset {sorted(_KNOWN_RESTRICTION_KEYS)}, got "
            f"{type(restriction).__name__}"
        )
    unknown = set(restriction) - _KNOWN_RESTRICTION_KEYS
    if unknown:
        raise StaticVerifyError(
            f"condition on {arg_name!r}: restriction keys {sorted(unknown)} are "
            "outside the enforced subset — refused at build time, never "
            "silently ignored"
        )
    if "type" in restriction and restriction["type"] not in _TYPE_NAMES:
        raise StaticVerifyError(
            f"condition on {arg_name!r}: unknown type {restriction['type']!r}"
        )
    if "pattern" in restriction:
        try:
            re.compile(restriction["pattern"])
        except re.error as exc:
            raise StaticVerifyError(
                f"condition on {arg_name!r}: invalid regex {restriction['pattern']!r}: {exc}"
            )


Policy = dict[str, list[PolicyRule]]
"""A policy: {tool_name: [PolicyRule, ...]} in Janus's internal shape."""


def sort_policy(policy: Policy) -> Policy:
    """Sort each tool's rules by (priority, -effect): deny before allow at
    equal priority — the fail-closed tie-break from Janus's ``_sort_policy``."""
    return {
        tool: sorted(rules, key=lambda r: (r.priority, -r.effect))
        for tool, rules in policy.items()
    }


def verify_policy_structure(policy: Policy, registry: DefinitionRegistry) -> list[str]:
    """Statically cross-validate a policy against registered definitions.

    Ports Janus's ``validate_policy_structure`` (loader.py) and hardens it:
    Janus returns *warnings*; here every finding is a hard error string and
    the caller must refuse the policy when the list is non-empty.

    Checks: every policy tool name is registered; every condition argument
    exists in the tool's pinned schema; every restriction is inside the
    enforced subset (checked again defensively at rule construction).
    """
    findings: list[str] = []
    for tool_name, rules in policy.items():
        definition = registry.get(tool_name)
        if definition is None:
            findings.append(f"policy references unknown tool {tool_name!r}")
            continue
        param_names = {p.name for p in definition.params}
        for rule in rules:
            for arg_name in rule.conditions:
                if arg_name not in param_names:
                    findings.append(
                        f"policy condition for {tool_name!r}.{arg_name!r} "
                        "references an argument absent from the pinned schema"
                    )
    return findings


# ---------------------------------------------------------------------------
# Argument value checking (stdlib subset of Janus's validate_argument)
# ---------------------------------------------------------------------------


def _check_value(arg_name: str, value: Any, restriction: dict[str, Any]) -> str | None:
    """Check one value against one restriction. Returns None on pass, else a
    reason string. Pure function; no exceptions for value mismatches."""
    expected = restriction.get("type")
    if expected == "string":
        if not isinstance(value, str):
            return f"{arg_name!r} must be string, got {type(value).__name__}"
        if "pattern" in restriction and not re.match(restriction["pattern"], value):
            return f"{arg_name!r} does not match pattern {restriction['pattern']!r}"
        if "minLength" in restriction and len(value) < restriction["minLength"]:
            return f"{arg_name!r} shorter than minLength {restriction['minLength']}"
        if "maxLength" in restriction and len(value) > restriction["maxLength"]:
            return f"{arg_name!r} longer than maxLength {restriction['maxLength']}"
    elif expected == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            return f"{arg_name!r} must be integer, got {type(value).__name__}"
        if "minimum" in restriction and value < restriction["minimum"]:
            return f"{arg_name!r} below minimum {restriction['minimum']}"
        if "maximum" in restriction and value > restriction["maximum"]:
            return f"{arg_name!r} above maximum {restriction['maximum']}"
    elif expected == "number":
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return f"{arg_name!r} must be number, got {type(value).__name__}"
        if "minimum" in restriction and value < restriction["minimum"]:
            return f"{arg_name!r} below minimum {restriction['minimum']}"
        if "maximum" in restriction and value > restriction["maximum"]:
            return f"{arg_name!r} above maximum {restriction['maximum']}"
    elif expected == "boolean":
        if not isinstance(value, bool):
            return f"{arg_name!r} must be boolean, got {type(value).__name__}"
    elif expected == "array":
        if not isinstance(value, list):
            return f"{arg_name!r} must be array, got {type(value).__name__}"
        if "minLength" in restriction and len(value) < restriction["minLength"]:
            return f"{arg_name!r} shorter than minLength {restriction['minLength']}"
        if "maxLength" in restriction and len(value) > restriction["maxLength"]:
            return f"{arg_name!r} longer than maxLength {restriction['maxLength']}"
    elif expected == "object":
        if not isinstance(value, dict):
            return f"{arg_name!r} must be object, got {type(value).__name__}"
    elif expected == "null":
        if value is not None:
            return f"{arg_name!r} must be null, got {type(value).__name__}"
    elif expected is not None:
        return f"{arg_name!r}: unknown restriction type {expected!r}"
    if "enum" in restriction and value not in restriction["enum"]:
        return f"{arg_name!r} value {value!r} not in enum {restriction['enum']!r}"
    return None


def _match_conditions(
    args: dict[str, Any], conditions: dict[str, dict[str, Any]], *, strict: bool
) -> tuple[bool, str | None]:
    """Janus ``_check_conditions`` semantics, ported:

    * allow rules under strict mode: a condition naming an absent argument
      FAILS the rule (the caller must not bypass a restriction by omitting
      the argument) — returns (False, reason).
    * deny rules: conditions on absent arguments match vacuously (fail
      closed) — absent args are skipped, not failed.
    """
    for arg_name, restriction in conditions.items():
        if arg_name in args:
            reason = _check_value(arg_name, args[arg_name], restriction)
            if reason is not None:
                return False, reason
        elif strict:
            return False, (
                f"allow rule skipped: restricted argument {arg_name!r} absent "
                "from the call (strict mode: omission must not satisfy a rule)"
            )
        # deny-rule vacuous match on absent args: skip (fail closed)
    return True, None


# ---------------------------------------------------------------------------
# The static pre-dispatch gate
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StaticVerdict:
    """The gate's answer. Denials are values, not exceptions: deny-before-
    dispatch means the runtime asks and gets an answer, never a throw."""

    verdict: str  # "allow" | "deny"
    tool: str
    reason: str
    definition_digest: str | None = None
    matched_rule: str | None = None

    @property
    def allowed(self) -> bool:
        return self.verdict == _VERDICT_ALLOW


def _deny(tool: str, reason: str, digest: str | None = None) -> StaticVerdict:
    return StaticVerdict(
        verdict=_VERDICT_DENY, tool=tool, reason=reason, definition_digest=digest
    )


class StaticVerifier:
    """Pure static pre-dispatch gate over (name, args-shape, caller).

    Constructed once from a ``DefinitionRegistry`` and a Janus-shaped
    policy. ``verify_call`` answers allow/deny WITHOUT executing anything:
    no handler runs, no side effects occur, no model is consulted. Every
    denial names the exact failing check so the audit record is
    self-explanatory.
    """

    def __init__(
        self,
        registry: DefinitionRegistry,
        policy: Policy,
        *,
        strict_conditions: bool = True,
    ) -> None:
        findings = verify_policy_structure(policy, registry)
        if findings:
            raise StaticVerifyError(
                "policy refused at build time: " + "; ".join(findings)
            )
        self._registry = registry
        self._policy = sort_policy(policy)
        self._strict = strict_conditions
        self._events: list[dict[str, Any]] = []

    @property
    def policy(self) -> Policy:
        return {tool: list(rules) for tool, rules in self._policy.items()}

    def events(self) -> list[dict[str, Any]]:
        return list(self._events)

    # -- the gate ------------------------------------------------------

    def verify_call(
        self,
        tool_name: str,
        args: dict[str, Any],
        caller_caps: frozenset[str] | set[str] = frozenset(),
    ) -> StaticVerdict:
        """Statically verify the (name, args-shape, caller) triple.

        Check order (first failure wins, all fail closed):
        1. tool registered (unknown → deny);
        2. definition not tampered + digest still pinned (tamper → deny);
        3. args-shape: no unknown args (smuggling), required present,
           types conform to the pinned schema;
        4. caller capabilities cover the tool's required_caps;
        5. Janus rule evaluation: priority order, strict allow semantics,
           deny-before-allow tie-break, default-deny.
        """
        if not isinstance(args, dict):
            return _deny(tool_name, "args must be a mapping")

        definition = self._registry.get(tool_name)
        if definition is None:
            return self._decide(tool_name, "unknown tool: not registered")

        digest = self._registry.pinned_digest(tool_name)
        if self._registry.is_tampered(tool_name):
            return self._decide(
                tool_name,
                "definition tamper: pinned digest no longer matches the "
                "registered definition — all calls denied until an audited "
                "force_reregister",
                digest,
            )
        if digest != definition.digest:
            # Defensive: the pin and the definition disagree without the
            # tamper flag having been set — fail closed anyway.
            return self._decide(
                tool_name, "definition digest mismatch (pin disagreement)", digest
            )

        # 3. args-shape against the pinned schema.
        shape_reason = self._check_shape(definition, args)
        if shape_reason is not None:
            return self._decide(tool_name, shape_reason, digest)

        # 4. caller capabilities.
        missing = set(definition.required_caps) - set(caller_caps)
        if missing:
            return self._decide(
                tool_name,
                f"caller lacks required capabilities: {sorted(missing)}",
                digest,
            )

        # 5. Janus rule evaluation.
        return self._evaluate_rules(tool_name, args, digest)

    # -- internals -----------------------------------------------------

    def _decide(
        self, tool_name: str, reason: str, digest: str | None = None
    ) -> StaticVerdict:
        verdict = _deny(tool_name, reason, digest)
        self._events.append(
            {
                "event": "static_verify.decision",
                "tool": tool_name,
                "verdict": verdict.verdict,
                "reason": reason,
                "digest": digest,
            }
        )
        return verdict

    def _check_shape(
        self, definition: ToolDefinition, args: dict[str, Any]
    ) -> str | None:
        """Returns None when the args-shape conforms, else a reason."""
        params = {p.name: p for p in definition.params}
        for arg_name in args:
            if arg_name not in params:
                return (
                    f"unknown argument {arg_name!r}: not in the pinned schema "
                    "(arg smuggling denied)"
                )
        for param in definition.params:
            if param.required and param.name not in args:
                return f"missing required argument {param.name!r}"
            if param.name in args:
                reason = _check_value(
                    param.name, args[param.name], {"type": param.type}
                    | ({"enum": list(param.enum)} if param.enum is not None else {})
                )
                if reason is not None:
                    return f"schema violation: {reason}"
        return None

    def _evaluate_rules(
        self, tool_name: str, args: dict[str, Any], digest: str | None
    ) -> StaticVerdict:
        """Janus ``_evaluate_rules`` semantics, returning verdicts."""
        rules = self._policy.get(tool_name)
        if not rules:
            return self._decide(
                tool_name,
                f"tool {tool_name!r} is not listed in the policy (default-deny)",
                digest,
            )
        skipped: list[str] = []
        for rule in rules:
            if rule.effect == ALLOW:
                ok, reason = _match_conditions(
                    args, rule.conditions, strict=self._strict
                )
                if ok:
                    verdict = StaticVerdict(
                        verdict=_VERDICT_ALLOW,
                        tool=tool_name,
                        reason=f"allow rule matched (priority={rule.priority})",
                        definition_digest=digest,
                        matched_rule=f"allow@{rule.priority}",
                    )
                    self._events.append(
                        {
                            "event": "static_verify.decision",
                            "tool": tool_name,
                            "verdict": verdict.verdict,
                            "reason": verdict.reason,
                            "digest": digest,
                        }
                    )
                    return verdict
                skipped.append(
                    f"allow rule (priority={rule.priority}) skipped: {reason}"
                )
            else:  # DENY — vacuous match on absent args (fail closed)
                ok, _ = _match_conditions(args, rule.conditions, strict=False)
                if ok:
                    return self._decide(
                        tool_name,
                        f"deny rule matched (priority={rule.priority})",
                        digest,
                    )
        detail = "; ".join(skipped) if skipped else "no allow rule matched"
        return self._decide(
            tool_name,
            f"no policy rule allowed this call (default-deny): {detail}",
            digest,
        )


# ---------------------------------------------------------------------------
# Audit anchoring
# ---------------------------------------------------------------------------


def static_verify_audit_events(verifier: StaticVerifier) -> list[dict[str, Any]]:
    """Decision + registry events, shaped for the ``audit.ndjson/1`` chain."""
    out: list[dict[str, Any]] = []
    for e in verifier.events():
        out.append({"kind": "static_verify.decision", **e})
    return out


__all__ = [
    "ALLOW",
    "DENY",
    "DefinitionRegistry",
    "DefinitionTamper",
    "Policy",
    "PolicyRule",
    "StaticVerifier",
    "StaticVerdict",
    "StaticVerifyError",
    "ToolDefinition",
    "ToolParam",
    "canonical_json",
    "definition_digest",
    "sha256_hex",
    "sort_policy",
    "static_verify_audit_events",
    "verify_policy_structure",
]
