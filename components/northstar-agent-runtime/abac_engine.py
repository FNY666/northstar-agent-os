"""ABAC engine interface (XACML / OPA-Rego attribute policies, simulated).

Research motivation: role-based access tops out at coarse groups; the
interesting governance question is *which attributes* gate a tool call.
XACML (OASIS) and OPA/Rego converged on the same bookkeeping shape:

- *attribute bundle*: subject / resource / action / environment each
  contribute attributes (role, clearance, owner, sensitivity,
  data-classification, ...);
- *DNF policies*: a policy matches when ANY rule matches; a rule
  matches when ALL of its conditions hold (AND of comparisons over
  attribute paths);
- *deny-overrides combining*: any matching deny wins over any
  matching allow; no match at all is a default deny -- the
  fail-closed direction.

This module is the *bookkeeping* half of that shape, pinned so the
runtime's authorization plumbing speaks one dialect:

- ``ABACEngine`` -- owns the ordered policy registry.
  ``add_policy()`` pins an immutable policy (effect + DNF rules),
  ``evaluate()`` runs deny-overrides over caller-supplied attribute
  bundles and returns a frozen ``Decision``, ``explain()`` renders a
  policy's rules into human-readable text.
- ``abac_engine_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``policy-added`` / ``evaluated`` / ``explained`` /
  ``rejected``); caller-supplied seqs only.

Fail-closed edges (fail loudly, never guess):

- Policy ids are non-empty ``str`` and unique; ``effect`` is
  ``allow`` or ``deny``; ``rules`` is a non-empty list of non-empty
  condition lists (a vacuous rule would always match -- refused at
  add time).
- Condition ``op`` is one of ``eq`` / ``ne`` / ``gt`` / ``gte`` /
  ``lt`` / ``lte`` / ``in`` / ``contains`` / ``startswith`` /
  ``endswith`` / ``regex`` -- unknown ops are refused at add time,
  never at evaluate time. ``target`` is one of ``subject`` /
  ``resource`` / ``action`` / ``context``.
- Attribute values must be canonicalizable: ``None`` / bool / int /
  ``str`` / float / lists / str-keyed mappings. ``NaN`` / ``inf``,
  integral floats or ints with ``abs >= 2**53`` are refused (the
  batch-5 JCS float-loss caveat). Bool is not int: ``True`` never
  equals ``1`` and never compares numerically.
- A *missing* attribute makes its condition false (never an error,
  never a guess). A *type mismatch* in a comparison (e.g. ``gt`` on a
  string, ``int`` vs ``float`` equality) makes the condition false.
  ``action`` conditions address the pseudo-attribute ``action.value``.
- Deny-overrides: any matching deny policy forces ``deny``; else any
  matching allow forces ``allow``; else ``deny`` (default deny).

Honest scope:

- This module books *host-reported* attributes. It cannot verify that
  ``subject.role == "admin"`` is true about the world; a lying host
  gets a lying decision ledger. The digest pins bind the *reported*
  bundles to the decision, not the truth.
- ``regex`` conditions compile the pattern at add time; evaluation
  uses ``re.search``. No glob, no negation operator -- say what you
  mean with an explicit rule.
- In-memory only: pair with the durable audit writer if policy
  history must survive a restart. ``main()`` self-checks the shape.
"""

from __future__ import annotations

import math
import re
import threading
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import hashlib as _hashlib
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return _hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
ABAC_ENGINE_VERSION = "abac-engine.v1"

#: Schema pin carried by records and audit events.
ABAC_ENGINE_SCHEMA = "northstar.abac-engine.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Policy effects.
ALLOW = "allow"
DENY = "deny"
_EFFECTS = (ALLOW, DENY)

#: Decisions.
DECISION_ALLOW = "allow"
DECISION_DENY = "deny"

#: Condition targets.
SUBJECT = "subject"
RESOURCE = "resource"
ACTION = "action"
CONTEXT = "context"
_TARGETS = (SUBJECT, RESOURCE, ACTION, CONTEXT)

#: The pseudo-attribute through which action conditions address the
#: action string itself.
ACTION_ATTRIBUTE = "value"

#: Comparison operators.
OP_EQ = "eq"
OP_NE = "ne"
OP_GT = "gt"
OP_GTE = "gte"
OP_LT = "lt"
OP_LTE = "lte"
OP_IN = "in"
OP_CONTAINS = "contains"
OP_STARTSWITH = "startswith"
OP_ENDSWITH = "endswith"
OP_REGEX = "regex"
_OPS = (
    OP_EQ, OP_NE, OP_GT, OP_GTE, OP_LT, OP_LTE, OP_IN,
    OP_CONTAINS, OP_STARTSWITH, OP_ENDSWITH, OP_REGEX,
)

#: Audit event kinds.
KIND_POLICY_ADDED = "policy-added"
KIND_EVALUATED = "evaluated"
KIND_EXPLAINED = "explained"
_KINDS = (
    KIND_POLICY_ADDED,
    KIND_EVALUATED,
    KIND_EXPLAINED,
)

#: Largest magnitude that survives canonical JSON intact (batch-5 caveat).
_MAX_SAFE_INT = 2 ** 53


class ABACError(Exception):
    """Base error for the ABAC engine."""


class DuplicatePolicyError(ABACError):
    """A policy with this id is already registered."""


class UnknownPolicyError(ABACError):
    """Policy id is not known to the registry."""


def _check_seq(seq: Any, what: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ABACError(f"{what} must be an int >= 0 (not bool)")
    return seq


def _check_str(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise ABACError(f"{what} must be a non-empty str")
    return value


def _check_attr_path(path: Any, what: str = "attribute") -> str:
    if not isinstance(path, str) or not path:
        raise ABACError(f"{what} must be a non-empty str")
    if path.startswith(".") or path.endswith(".") or ".." in path:
        raise ABACError(f"{what} must be a dotted path with no empty segments")
    for segment in path.split("."):
        if not segment:
            raise ABACError(f"{what} must be a dotted path with no empty segments")
    return path


def _canonical(value: Any) -> Any:
    """Type-tagged canonical form of an attribute value.

    Bool is distinct from int; NaN/inf and abs >= 2**53 numbers are
    refused fail-closed (the batch-5 JCS float-loss caveat).
    """
    if value is None:
        return ["none"]
    if isinstance(value, bool):
        return ["bool", value]
    if isinstance(value, int):
        if abs(value) >= _MAX_SAFE_INT:
            raise ABACError(f"int magnitude >= 2**53 cannot be pinned safely: {value!r}")
        return ["int", value]
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ABACError("NaN/inf attribute values are refused")
        if value.is_integer() and abs(value) >= _MAX_SAFE_INT:
            raise ABACError(f"float magnitude >= 2**53 cannot be pinned safely: {value!r}")
        return ["float", repr(value)]
    if isinstance(value, str):
        return ["str", value]
    if isinstance(value, (list, tuple)):
        return ["list", [_canonical(v) for v in value]]
    if isinstance(value, Mapping):
        items = []
        for k, v in value.items():
            if not isinstance(k, str) or not k:
                raise ABACError("attribute mapping keys must be non-empty str")
            items.append([k, _canonical(v)])
        items.sort(key=lambda kv: kv[0])
        return ["map", items]
    raise ABACError(f"value of type {type(value).__name__} is not canonicalizable")


def _pin(*parts: Any) -> str:
    return "sha256:" + jcs_sha256_hex(list(parts))


def _check_attrs(value: Any, what: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ABACError(f"{what} must be a mapping of attributes")
    _canonical(value)  # validates canonicalizability now, fail-closed
    return value


@dataclass(frozen=True)
class RuleCondition:
    """One atomic condition: target.attribute op value."""

    target: str
    attribute: str
    op: str
    value: Any


@dataclass(frozen=True)
class PolicyRecord:
    """One pinned ABAC policy: effect + DNF rules."""

    policy_id: str
    effect: str
    rules: Tuple[Tuple[RuleCondition, ...], ...]
    seq: int
    digest: str
    version: str = ABAC_ENGINE_VERSION
    schema: str = ABAC_ENGINE_SCHEMA


@dataclass(frozen=True)
class Decision:
    """One frozen deny-overrides evaluation decision."""

    decision: str
    matched_policies: Tuple[str, ...]
    subject_digest: str
    resource_digest: str
    context_digest: str
    action: str
    seq: int
    digest: str
    version: str = ABAC_ENGINE_VERSION
    schema: str = ABAC_ENGINE_SCHEMA


@dataclass(frozen=True)
class PolicyExplanation:
    """Human-readable rendering of one policy's rules."""

    policy_id: str
    effect: str
    rendered_rules: Tuple[str, ...]
    rule_count: int
    seq: int
    digest: str
    version: str = ABAC_ENGINE_VERSION
    schema: str = ABAC_ENGINE_SCHEMA


def abac_engine_audit_event(kind: str, seq: int, **detail: Any) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the ABAC engine."""
    if kind not in _KINDS:
        raise ABACError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "abac_engine",
        "module_version": ABAC_ENGINE_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


def _normalize_condition(raw: Any) -> RuleCondition:
    """Validate and normalize one condition dict / RuleCondition."""
    if isinstance(raw, RuleCondition):
        target, attribute, op, value = raw.target, raw.attribute, raw.op, raw.value
    elif isinstance(raw, Mapping):
        try:
            target = raw["target"]
            attribute = raw["attribute"]
            op = raw["op"]
            value = raw["value"]
        except KeyError as exc:
            raise ABACError(f"condition is missing key: {exc.args[0]!r}") from exc
    else:
        raise ABACError("conditions must be mappings or RuleCondition")
    if target not in _TARGETS:
        raise ABACError(f"condition target must be one of {_TARGETS}, got {target!r}")
    _check_attr_path(attribute)
    if op not in _OPS:
        raise ABACError(f"unknown condition op: {op!r}")
    if op in (OP_GT, OP_GTE, OP_LT, OP_LTE):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ABACError(f"op {op!r} needs a numeric (non-bool) value")
        if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
            raise ABACError(f"op {op!r} refuses NaN/inf")
    elif op in (OP_STARTSWITH, OP_ENDSWITH, OP_REGEX):
        if not isinstance(value, str):
            raise ABACError(f"op {op!r} needs a str value")
        if op == OP_REGEX:
            try:
                re.compile(value)
            except re.error as exc:
                raise ABACError(f"bad regex in condition: {exc}") from exc
    elif op == OP_IN:
        if not isinstance(value, (list, tuple)):
            raise ABACError("op 'in' needs a list value")
    _canonical(value)  # fail-closed on NaN/inf/>2**53/non-canonical
    return RuleCondition(target=target, attribute=attribute, op=op, value=value)


def _lookup(attrs: Mapping[str, Any], path: str) -> Tuple[bool, Any]:
    """Dotted-path lookup into nested mappings."""
    current: Any = attrs
    for segment in path.split("."):
        if not isinstance(current, Mapping) or segment not in current:
            return False, None
        current = current[segment]
    return True, current


def _tag(value: Any) -> str:
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    return "other"


def _safe_eq(actual: Any, expected: Any) -> bool:
    """Type-aware equality: bool is not int, int is not float."""
    tag_a, tag_e = _tag(actual), _tag(expected)
    if tag_a != tag_e or tag_a == "other":
        return False
    if tag_a == "float" and (math.isnan(actual) or math.isnan(expected)):
        return False
    return bool(actual == expected)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _condition_matches(
    cond: RuleCondition,
    subject: Mapping[str, Any],
    resource: Mapping[str, Any],
    action: str,
    context: Mapping[str, Any],
) -> bool:
    targets = {
        SUBJECT: subject,
        RESOURCE: resource,
        ACTION: {ACTION_ATTRIBUTE: action},
        CONTEXT: context,
    }
    found, actual = _lookup(targets[cond.target], cond.attribute)
    if not found:
        return False  # missing attribute => condition false, never a guess
    op, expected = cond.op, cond.value
    if op == OP_EQ:
        return _safe_eq(actual, expected)
    if op == OP_NE:
        return not _safe_eq(actual, expected)
    if op in (OP_GT, OP_GTE, OP_LT, OP_LTE):
        if not _is_number(actual) or not _is_number(expected):
            return False
        if isinstance(actual, float) and math.isnan(actual):
            return False
        if op == OP_GT:
            return bool(actual > expected)
        if op == OP_GTE:
            return bool(actual >= expected)
        if op == OP_LT:
            return bool(actual < expected)
        return bool(actual <= expected)
    if op == OP_IN:
        return any(_safe_eq(actual, item) for item in expected)
    if op == OP_CONTAINS:
        if isinstance(actual, str) and isinstance(expected, str):
            return expected in actual
        if isinstance(actual, (list, tuple)):
            return any(_safe_eq(item, expected) for item in actual)
        return False
    if op == OP_STARTSWITH:
        return isinstance(actual, str) and actual.startswith(expected)
    if op == OP_ENDSWITH:
        return isinstance(actual, str) and actual.endswith(expected)
    if op == OP_REGEX:
        return isinstance(actual, str) and re.search(expected, actual) is not None
    return False  # unreachable: op validated at add time


def _rule_matches(
    rule: Tuple[RuleCondition, ...],
    subject: Mapping[str, Any],
    resource: Mapping[str, Any],
    action: str,
    context: Mapping[str, Any],
) -> bool:
    return all(
        _condition_matches(c, subject, resource, action, context) for c in rule
    )


def _render_condition(cond: RuleCondition) -> str:
    return f"{cond.target}.{cond.attribute} {cond.op} {cond.value!r}"


class ABACEngine:
    """Attribute-based access control: deny-overrides policy evaluation."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._policies: dict = {}  # policy_id -> PolicyRecord (insertion order)

    # -- policies -----------------------------------------------------

    def add_policy(
        self,
        policy_id: str,
        effect: str,
        rules: Any,
        seq: int,
    ) -> PolicyRecord:
        """Register an immutable policy with DNF rules (OR of ANDs)."""
        _check_str(policy_id, "policy_id")
        if effect not in _EFFECTS:
            raise ABACError(f"effect must be one of {_EFFECTS}, got {effect!r}")
        _check_seq(seq)
        if not isinstance(rules, (list, tuple)) or not rules:
            raise ABACError("rules must be a non-empty list of condition lists")
        norm_rules = []
        for rule in rules:
            if not isinstance(rule, (list, tuple)) or not rule:
                raise ABACError("each rule must be a non-empty list of conditions")
            norm_rules.append(tuple(_normalize_condition(c) for c in rule))
        with self._lock:
            if policy_id in self._policies:
                raise DuplicatePolicyError(f"policy already registered: {policy_id!r}")
            canon_rules = tuple(
                tuple(_canonical({"target": c.target, "attribute": c.attribute,
                                  "op": c.op, "value": c.value}) for c in rule)
                for rule in norm_rules
            )
            digest = _pin(["policy", policy_id, effect, list(canon_rules), seq])
            record = PolicyRecord(
                policy_id=policy_id,
                effect=effect,
                rules=tuple(norm_rules),
                seq=seq,
                digest=digest,
            )
            self._policies[policy_id] = record
            return record

    def policy(self, policy_id: str) -> PolicyRecord:
        """Return one policy record; unknown ids are refused."""
        _check_str(policy_id, "policy_id")
        with self._lock:
            try:
                return self._policies[policy_id]
            except KeyError:
                raise UnknownPolicyError(f"unknown policy: {policy_id!r}") from None

    def policies(self) -> Tuple[str, ...]:
        """Sorted policy ids currently registered."""
        with self._lock:
            return tuple(sorted(self._policies))

    def policy_count(self) -> int:
        with self._lock:
            return len(self._policies)

    # -- evaluation ----------------------------------------------------

    def evaluate(
        self,
        subject: Mapping[str, Any],
        resource: Mapping[str, Any],
        action: str,
        seq: int,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Decision:
        """Deny-overrides evaluation over the attribute bundles."""
        _check_attrs(subject, "subject")
        _check_attrs(resource, "resource")
        _check_str(action, "action")
        _check_seq(seq)
        ctx = {} if context is None else _check_attrs(context, "context")
        with self._lock:
            matched = []
            for policy_id, record in self._policies.items():
                if any(
                    _rule_matches(rule, subject, resource, action, ctx)
                    for rule in record.rules
                ):
                    matched.append(record)
            denies = [r for r in matched if r.effect == DENY]
            allows = [r for r in matched if r.effect == ALLOW]
            decision = DECISION_DENY
            if denies:
                decision = DECISION_DENY
            elif allows:
                decision = DECISION_ALLOW
            matched_ids = tuple(r.policy_id for r in matched)
            subject_digest = _pin(["subject", _canonical(subject)])
            resource_digest = _pin(["resource", _canonical(resource)])
            context_digest = _pin(["context", _canonical(ctx)])
            digest = _pin([
                "decision", decision, list(matched_ids),
                subject_digest, resource_digest, context_digest, action, seq,
            ])
            return Decision(
                decision=decision,
                matched_policies=matched_ids,
                subject_digest=subject_digest,
                resource_digest=resource_digest,
                context_digest=context_digest,
                action=action,
                seq=seq,
                digest=digest,
            )

    # -- explanation ----------------------------------------------------

    def explain(self, policy_id: str, seq: int) -> PolicyExplanation:
        """Render one policy's rules as human-readable text."""
        _check_seq(seq)
        record = self.policy(policy_id)  # raises UnknownPolicyError
        rendered = tuple(
            " AND ".join(_render_condition(c) for c in rule)
            for rule in record.rules
        )
        digest = _pin(["explanation", policy_id, record.effect,
                       list(rendered), record.digest, seq])
        return PolicyExplanation(
            policy_id=policy_id,
            effect=record.effect,
            rendered_rules=rendered,
            rule_count=len(record.rules),
            seq=seq,
            digest=digest,
        )


def main() -> None:
    engine = ABACEngine()
    engine.add_policy(
        "admins-allow", "allow",
        [[{"target": "subject", "attribute": "role", "op": "eq", "value": "admin"}]],
        seq=1,
    )
    engine.add_policy(
        "banned-deny", "deny",
        [[{"target": "subject", "attribute": "banned", "op": "eq", "value": True}]],
        seq=2,
    )
    d1 = engine.evaluate({"role": "admin"}, {"owner": "x"}, "read", seq=3)
    assert d1.decision == "allow", d1
    d2 = engine.evaluate({"role": "admin", "banned": True}, {"owner": "x"}, "read", seq=4)
    assert d2.decision == "deny", d2  # deny-overrides
    d3 = engine.evaluate({"role": "viewer"}, {"owner": "x"}, "read", seq=5)
    assert d3.decision == "deny", d3  # default deny
    expl = engine.explain("admins-allow", seq=6)
    assert expl.rule_count == 1 and expl.effect == "allow", expl
    print("abac-engine OK: add, evaluate (deny-overrides), default-deny, explain")


if __name__ == "__main__":
    main()
