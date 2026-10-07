"""OPA-style policy engine: Rego-like allow/deny rules over input documents.

Where ``flag_service.py`` answers "is this subject in the cohort", the policy
engine answers the authorization question directly: given a host-reported
input document (subject, action, resource, environment), what does the loaded
policy package decide? The shape follows OPA/Rego discipline -- a policy
package is a set of ``allow``/``deny`` rules evaluated against an input
document -- but the rule language is a small deterministic subset of JSON,
not Rego itself.

Rule language::

    policy = {
        "version": "policy.v1",
        "default_allow": False,
        "rules": [
            {
                "id": "admins-may-delete",
                "decision": "allow",
                "when": {"path": "subject.role", "op": "eq", "value": "admin"},
            },
            {
                "id": "block-suspended",
                "decision": "deny",
                "when": {"all": [
                    {"path": "subject.status", "op": "eq", "value": "suspended"},
                    {"path": "action", "op": "ne", "value": "read"},
                ]},
            },
        ],
    }

A rule fires when its ``when`` clause matches the input. Dotted paths walk
mappings (``subject.role`` reads ``input["subject"]["role"]``). Ops: ``eq``,
``ne``, ``gt``, ``gte``, ``lt``, ``lte``, ``in``, ``contains``,
``startswith``, ``endswith``, ``exists``. Combinators: ``all`` (every
condition holds), ``any`` (at least one holds), ``not`` (inner condition
must not hold).

Decision semantics (OPA-like, fail-closed):

  1. Any ``deny`` rule fires -> ``allowed=False`` (deny overrides allow).
  2. Else any ``allow`` rule fires -> ``allowed=True``.
  3. Else the policy's ``default_allow`` (normally ``False``).

``load()`` registers a policy package and pins a ``sha256:`` digest over
the canonical body; ``eval()`` returns a frozen ``DecisionReport``;
``explain()`` returns a frozen ``ExplanationReport`` with a per-condition
trace for every rule, so a denied request can name the exact rule and
condition that failed. Both records pin the policy digest that produced
them, making the deciding rule set auditable.

House style: frozen dataclasses, fail-closed validation (``TypeError`` on
wrong types -- bool is not a number, ``ValueError`` on bad values),
stdlib-only, version/schema pins, ``main()`` self-check. No wall-clock;
caller-supplied int seqs sequence every mutation.

Honest scope: the engine evaluates *host-reported* input -- it cannot prove
the input is true, observe the real world, or stop a host that ignores the
verdict. ``allowed=True`` means "the rules as pinned fired allow", never
"the action is safe". ``exists``/``ne`` on missing paths are documented
conventions, not ground truth about absent data. Policies pin host-reported
documents; the engine is a decision bookkeeper, not an enforcer.

Version pin: policy-engine.v1
Schema pin: northstar.policy-engine.v1
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Tuple

POLICY_ENGINE_VERSION = "policy-engine.v1"
SCHEMA_PIN = "northstar.policy-engine.v1"

_HASH_DOMAIN = "northstar.policy-engine.v1"

#: Condition operators understood by ``when`` clauses.
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
OP_EXISTS = "exists"

_CONDITION_OPS: FrozenSet[str] = frozenset({
    OP_EQ, OP_NE, OP_GT, OP_GTE, OP_LT, OP_LTE, OP_IN, OP_CONTAINS,
    OP_STARTSWITH, OP_ENDSWITH, OP_EXISTS,
})

_DECISIONS: FrozenSet[str] = frozenset({"allow", "deny"})

_MISSING = object()  # sentinel for "path did not resolve"


class PolicyEngineError(Exception):
    """Base error for the policy engine."""


class DuplicatePolicyError(PolicyEngineError):
    """A policy name is already registered."""


class UnknownPolicyError(PolicyEngineError):
    """The named policy does not exist."""


class InvalidPolicyError(PolicyEngineError):
    """The policy document is malformed (fail-closed)."""


class InvalidInputError(PolicyEngineError):
    """The input document is malformed (fail-closed)."""


def _check_str(name: str, value: object, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a str, got {type(value).__name__}")
    if not allow_empty and not value:
        raise ValueError(f"{name} must be non-empty")
    if "\x00" in value:
        raise ValueError(f"{name} must not contain NUL")
    return value


def _check_bool(name: str, value: object) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{name} must be a bool, got {type(value).__name__}")
    return value


def _check_seq(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"seq must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError("seq must be >= 0")
    return value


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _check_finite_number(name: str, value: object) -> Any:
    if not _is_number(value):
        raise TypeError(f"{name} must be a number, got {type(value).__name__}")
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError(f"{name} must be finite")
    return value


def _canonicalize(value: Any, path: str) -> Any:
    """Fail-closed recursive canonicalization for digest pinning."""
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, bool):
        return {"$bool": value}
    if isinstance(value, int):
        if abs(value) > 2**53:
            raise InvalidPolicyError(f"{path}: ints > 2^53 refused (JCS float-loss)")
        return {"$int": value}
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise InvalidPolicyError(f"{path}: NaN/inf refused")
        if value.is_integer() and abs(value) > 2**53:
            raise InvalidPolicyError(f"{path}: integral floats > 2^53 refused")
        return {"$float": repr(value)}
    if isinstance(value, (list, tuple)):
        return [(_canonicalize(v, f"{path}[{i}]")) for i, v in enumerate(value)]
    if isinstance(value, Mapping):
        out = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise InvalidPolicyError(f"{path}: mapping keys must be str")
            out[k] = _canonicalize(v, f"{path}.{k}")
        return out
    raise InvalidPolicyError(f"{path}: unsupported value type {type(value).__name__}")


def _encode(obj: Any) -> bytes:
    import json

    return json.dumps(
        _canonicalize(obj, "$"), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _digest(*parts: bytes) -> str:
    h = hashlib.sha256(_HASH_DOMAIN.encode())
    for p in parts:
        h.update(b"\x00" + p)
    return "sha256:" + h.hexdigest()


def _resolve_path(doc: Any, path: str) -> Any:
    """Walk dotted path over nested mappings; missing -> _MISSING."""
    current = doc
    for part in path.split("."):
        if isinstance(current, Mapping) and part in current:
            current = current[part]
        else:
            return _MISSING
    return current


def _values_equal(a: Any, b: Any) -> bool:
    """Type-strict equality (bool != int, matching the JCS caveat line)."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a is b
    if _is_number(a) and _is_number(b):
        return a == b
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    if a is None and b is None:
        return True
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
        return (
            len(a) == len(b)
            and all(_values_equal(x, y) for x, y in zip(a, b))
        )
    if isinstance(a, Mapping) and isinstance(b, Mapping):
        return (
            set(a.keys()) == set(b.keys())
            and all(_values_equal(a[k], b[k]) for k in a)
        )
    return False


@dataclass(frozen=True)
class ConditionTrace:
    """How one leaf condition evaluated."""
    path: str
    op: str
    expected: Any
    actual: Any
    matched: bool
    detail: str


@dataclass(frozen=True)
class RuleTrace:
    """How one rule evaluated."""
    rule_id: str
    decision: str
    fired: bool
    conditions: Tuple[ConditionTrace, ...]
    digest: str


@dataclass(frozen=True)
class PolicyRecord:
    """A loaded policy package."""
    name: str
    version: str
    default_allow: bool
    rule_count: int
    digest: str
    seq: int


@dataclass(frozen=True)
class DecisionReport:
    """The verdict of one eval()."""
    policy_name: str
    policy_digest: str
    allowed: bool
    reason: str  # "deny" | "allow" | "default"
    fired_allow: Tuple[str, ...]
    fired_deny: Tuple[str, ...]
    digest: str
    seq: int


@dataclass(frozen=True)
class ExplanationReport:
    """Per-rule traces for one eval()."""
    policy_name: str
    policy_digest: str
    allowed: bool
    rules: Tuple[RuleTrace, ...]
    digest: str
    seq: int


class PolicyEngine:
    """OPA-shaped policy store: load packages, eval inputs, explain verdicts."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._policies: Dict[str, Tuple[PolicyRecord, List[Tuple[str, str, Any]]]] = {}
        # name -> (record, [(rule_id, decision, when_clause)])

    # -- validation -------------------------------------------------------

    def _validate_condition(self, cond: Any, where: str) -> Any:
        if not isinstance(cond, Mapping):
            raise InvalidPolicyError(f"{where}: condition must be a mapping")
        keys = set(cond.keys())
        if keys == {"all"}:
            parts = cond["all"]
            if not isinstance(parts, (list, tuple)) or not parts:
                raise InvalidPolicyError(f"{where}: 'all' needs a non-empty list")
            return {"all": [self._validate_condition(p, where) for p in parts]}
        if keys == {"any"}:
            parts = cond["any"]
            if not isinstance(parts, (list, tuple)) or not parts:
                raise InvalidPolicyError(f"{where}: 'any' needs a non-empty list")
            return {"any": [self._validate_condition(p, where) for p in parts]}
        if keys == {"not"}:
            return {"not": self._validate_condition(cond["not"], where)}
        if keys == {"path", "op"} or keys == {"path", "op", "value"}:
            path = _check_str(f"{where}: path", cond["path"])
            op = _check_str(f"{where}: op", cond["op"])
            if op not in _CONDITION_OPS:
                raise InvalidPolicyError(
                    f"{where}: unknown op {op!r}; allowed: {sorted(_CONDITION_OPS)}"
                )
            if op == OP_EXISTS:
                value = cond.get("value", True)
                _check_bool(f"{where}: value for 'exists'", value)
            else:
                if "value" not in cond:
                    raise InvalidPolicyError(f"{where}: op {op!r} requires 'value'")
                _canonicalize(cond["value"], f"{where}.value")
                if op in (OP_GT, OP_GTE, OP_LT, OP_LTE):
                    _check_finite_number(f"{where}: value for {op}", cond["value"])
                if op == OP_IN and not isinstance(cond["value"], (list, tuple)):
                    raise InvalidPolicyError(f"{where}: 'in' value must be a list")
                if op in (OP_STARTSWITH, OP_ENDSWITH):
                    _check_str(f"{where}: value for {op}", cond["value"])
            return {"path": path, "op": op, "value": cond.get("value")}
        raise InvalidPolicyError(
            f"{where}: bad condition shape {sorted(keys)}; "
            "expected {{path,op[,value]}} or {{all/any/not}}"
        )

    # -- load -------------------------------------------------------------

    def load(self, name: str, policy: Mapping[str, Any], seq: int) -> PolicyRecord:
        """Register a policy package under ``name``; duplicate names refused."""
        _check_str("name", name)
        _check_seq(seq)
        if not isinstance(policy, Mapping):
            raise InvalidPolicyError("policy must be a mapping")
        default_allow = policy.get("default_allow", False)
        _check_bool("default_allow", default_allow)
        rules = policy.get("rules", [])
        if not isinstance(rules, (list, tuple)):
            raise InvalidPolicyError("policy.rules must be a list")
        seen: List[str] = []
        normalized: List[Tuple[str, str, Any]] = []
        for i, rule in enumerate(rules):
            where = f"rules[{i}]"
            if not isinstance(rule, Mapping):
                raise InvalidPolicyError(f"{where}: rule must be a mapping")
            rid = _check_str(f"{where}: id", rule.get("id"))
            if rid in seen:
                raise InvalidPolicyError(f"{where}: duplicate rule id {rid!r}")
            seen.append(rid)
            decision = rule.get("decision")
            if decision not in _DECISIONS:
                raise InvalidPolicyError(
                    f"{where}: decision must be 'allow' or 'deny'"
                )
            if "when" not in rule:
                raise InvalidPolicyError(f"{where}: rule requires 'when'")
            when = self._validate_condition(rule["when"], f"{where}.when")
            normalized.append((rid, decision, when))
        canon = _canonicalize(
            {"name": name, "default_allow": default_allow,
             "rules": [{"id": r, "decision": d, "when": w} for r, d, w in normalized]},
            "policy",
        )
        record = PolicyRecord(
            name=name,
            version=POLICY_ENGINE_VERSION,
            default_allow=default_allow,
            rule_count=len(normalized),
            digest=_digest(_encode(canon)),
            seq=seq,
        )
        with self._lock:
            if name in self._policies:
                raise DuplicatePolicyError(f"policy {name!r} already loaded")
            self._policies[name] = (record, normalized)
        return record

    def policy(self, name: str) -> PolicyRecord:
        """Return the record for a loaded policy."""
        _check_str("name", name)
        with self._lock:
            if name not in self._policies:
                raise UnknownPolicyError(f"unknown policy {name!r}")
            return self._policies[name][0]

    def policies(self) -> Tuple[str, ...]:
        """Sorted names of loaded policies."""
        with self._lock:
            return tuple(sorted(self._policies))

    # -- evaluation -------------------------------------------------------

    def _validate_input(self, input_doc: Any) -> Mapping[str, Any]:
        if not isinstance(input_doc, Mapping):
            raise InvalidInputError(
                f"input must be a mapping, got {type(input_doc).__name__}"
            )
        _canonicalize(input_doc, "input")  # fail-closed on NaN/inf/huge ints
        return input_doc

    def _leaf_trace(self, cond: Mapping[str, Any], input_doc: Any) -> ConditionTrace:
        path, op, expected = cond["path"], cond["op"], cond.get("value")
        actual = _resolve_path(input_doc, path)
        if op == OP_EXISTS:
            exists = actual is not _MISSING
            matched = exists == expected
            detail = (
                f"path {path!r} {'exists' if exists else 'missing'}; "
                f"expected exists={expected}"
            )
            return ConditionTrace(path, op, expected, None, matched, detail)
        if actual is _MISSING:
            return ConditionTrace(
                path, op, expected, None, False,
                f"path {path!r} missing; op {op!r} fails closed",
            )
        matched = self._compare(op, actual, expected)
        return ConditionTrace(
            path, op, expected, actual, matched,
            f"{actual!r} {op} {expected!r} -> {matched}",
        )

    def _compare(self, op: str, actual: Any, expected: Any) -> bool:
        if op == OP_EQ:
            return _values_equal(actual, expected)
        if op == OP_NE:
            return not _values_equal(actual, expected)
        if op in (OP_GT, OP_GTE, OP_LT, OP_LTE):
            if not (_is_number(actual) and _is_number(expected)):
                return False
            return {
                OP_GT: actual > expected,
                OP_GTE: actual >= expected,
                OP_LT: actual < expected,
                OP_LTE: actual <= expected,
            }[op]
        if op == OP_IN:
            return any(_values_equal(actual, item) for item in expected)
        if op == OP_CONTAINS:
            if isinstance(actual, str) and isinstance(expected, str):
                return expected in actual
            if isinstance(actual, (list, tuple)):
                return any(_values_equal(item, expected) for item in actual)
            return False
        if op == OP_STARTSWITH:
            return isinstance(actual, str) and actual.startswith(expected)
        if op == OP_ENDSWITH:
            return isinstance(actual, str) and actual.endswith(expected)
        return False  # unreachable: validated at load

    def _eval_clause(
        self, clause: Any, input_doc: Any, traces: List[ConditionTrace]
    ) -> bool:
        if "path" in clause:
            trace = self._leaf_trace(clause, input_doc)
            traces.append(trace)
            return trace.matched
        if "all" in clause:
            results = [self._eval_clause(c, input_doc, traces) for c in clause["all"]]
            return all(results)
        if "any" in clause:
            results = [self._eval_clause(c, input_doc, traces) for c in clause["any"]]
            return any(results)
        if "not" in clause:
            before = len(traces)
            inner = self._eval_clause(clause["not"], input_doc, traces)
            # Rewrite the inner traces as negated annotations for readability.
            negated = []
            for t in traces[before:]:
                negated.append(
                    ConditionTrace(
                        t.path, f"not({t.op})", t.expected, t.actual,
                        not t.matched, f"not: inner {'did not match' if not t.matched else 'matched'}",
                    )
                )
            traces[before:] = negated
            return not inner
        return False  # unreachable: validated at load

    def _eval_rules(
        self, name: str, input_doc: Mapping[str, Any]
    ) -> Tuple[PolicyRecord, List[RuleTrace]]:
        with self._lock:
            if name not in self._policies:
                raise UnknownPolicyError(f"unknown policy {name!r}")
            record, rules = self._policies[name]
            snapshot = list(rules)
        traces: List[RuleTrace] = []
        for rid, decision, when in snapshot:
            leaf_traces: List[ConditionTrace] = []
            fired = self._eval_clause(when, input_doc, leaf_traces)
            traces.append(
                RuleTrace(
                    rule_id=rid,
                    decision=decision,
                    fired=fired,
                    conditions=tuple(leaf_traces),
                    digest=_digest(
                        _encode({"policy": record.digest, "rule": rid, "fired": fired})
                    ),
                )
            )
        return record, traces

    def eval(
        self,
        input_doc: Mapping[str, Any],
        seq: int,
        policy_name: Optional[str] = None,
    ) -> DecisionReport:
        """Evaluate ``input_doc``; return a frozen ``DecisionReport``."""
        _check_seq(seq)
        input_doc = self._validate_input(input_doc)
        name = policy_name or self._default_policy()
        record, traces = self._eval_rules(name, input_doc)
        fired_deny = tuple(t.rule_id for t in traces if t.decision == "deny" and t.fired)
        fired_allow = tuple(t.rule_id for t in traces if t.decision == "allow" and t.fired)
        if fired_deny:
            allowed, reason = False, "deny"
        elif fired_allow:
            allowed, reason = True, "allow"
        else:
            allowed, reason = record.default_allow, "default"
        report = DecisionReport(
            policy_name=name,
            policy_digest=record.digest,
            allowed=allowed,
            reason=reason,
            fired_allow=fired_allow,
            fired_deny=fired_deny,
            digest=_digest(
                _encode({
                    "policy": record.digest,
                    "allowed": allowed,
                    "reason": reason,
                    "fired_allow": list(fired_allow),
                    "fired_deny": list(fired_deny),
                })
            ),
            seq=seq,
        )
        return report

    def explain(
        self,
        input_doc: Mapping[str, Any],
        seq: int,
        policy_name: Optional[str] = None,
    ) -> ExplanationReport:
        """Evaluate and return a frozen per-rule trace."""
        _check_seq(seq)
        input_doc = self._validate_input(input_doc)
        name = policy_name or self._default_policy()
        record, traces = self._eval_rules(name, input_doc)
        fired_deny = any(t.decision == "deny" and t.fired for t in traces)
        fired_allow = any(t.decision == "allow" and t.fired for t in traces)
        allowed = record.default_allow if not (fired_deny or fired_allow) else fired_allow
        if fired_deny:
            allowed = False
        return ExplanationReport(
            policy_name=name,
            policy_digest=record.digest,
            allowed=allowed,
            rules=tuple(traces),
            digest=_digest(
                _encode({
                    "policy": record.digest,
                    "allowed": allowed,
                    "rule_traces": [t.digest for t in traces],
                })
            ),
            seq=seq,
        )

    def _default_policy(self) -> str:
        with self._lock:
            names = sorted(self._policies)
        if len(names) != 1:
            raise PolicyEngineError(
                f"policy_name required: {len(names)} policies loaded"
            )
        return names[0]


def policy_engine_audit_event(kind: str, seq: int, **fields: Any) -> dict:
    """Shape an ``audit.ndjson/1`` record for a policy-engine event."""
    allowed = {"policy-loaded", "evaluated", "explained", "rejected"}
    if kind not in allowed:
        raise PolicyEngineError(
            f"unknown audit kind {kind!r}; allowed: {sorted(allowed)}"
        )
    _check_seq(seq)
    record = {
        "schema": "audit.ndjson/1",
        "kind": f"policy-engine.{kind}",
        "module": POLICY_ENGINE_VERSION,
        "seq": seq,
    }
    record.update(fields)
    return record


def main() -> None:
    """Self-check: load a package, eval allow/deny/default, explain."""
    eng = PolicyEngine()
    policy = {
        "default_allow": False,
        "rules": [
            {
                "id": "admins-may-write",
                "decision": "allow",
                "when": {"path": "subject.role", "op": "eq", "value": "admin"},
            },
            {
                "id": "block-suspended",
                "decision": "deny",
                "when": {
                    "all": [
                        {"path": "subject.status", "op": "eq", "value": "suspended"},
                        {"path": "action", "op": "ne", "value": "read"},
                    ]
                },
            },
        ],
    }
    rec = eng.load("rbac", policy, seq=1)
    assert rec.rule_count == 2 and rec.digest.startswith("sha256:")

    admin = {"subject": {"role": "admin", "status": "active"}, "action": "write"}
    rep = eng.eval(admin, seq=2)
    assert rep.allowed and rep.reason == "allow", rep

    suspended_admin = {
        "subject": {"role": "admin", "status": "suspended"},
        "action": "write",
    }
    rep2 = eng.eval(suspended_admin, seq=3)
    assert not rep2.allowed and rep2.reason == "deny", rep2
    assert rep2.fired_deny == ("block-suspended",)

    guest = {"subject": {"role": "guest", "status": "active"}, "action": "read"}
    rep3 = eng.eval(guest, seq=4)
    assert not rep3.allowed and rep3.reason == "default", rep3

    expl = eng.explain(suspended_admin, seq=5)
    assert not expl.allowed and len(expl.rules) == 2
    by_id = {t.rule_id: t for t in expl.rules}
    assert by_id["block-suspended"].fired
    assert len(by_id["block-suspended"].conditions) == 2

    evt = policy_engine_audit_event("evaluated", 6, policy="rbac", allowed=False)
    assert evt["schema"] == "audit.ndjson/1"
    print("policy-engine OK: load, eval, deny-overrides, default-deny, explain")


if __name__ == "__main__":
    main()
