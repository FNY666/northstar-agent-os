"""Trust & safety policy engine (twenty-ninth batch).

Deterministic, single-host bookkeeping for platform trust & safety
policy definition, content/action enforcement decisions, and audit
summaries. Informed by the policy-engine pattern (Open Policy Agent /
platform T&S playbooks): policies are pinned rule sets, enforcement
is a pure decision function over declared signals, and every decision
is digest-sealed and audit-logged.

House rules: frozen dataclasses, caller-supplied strictly-increasing
int ``seq`` (no wall-clock), RLock-guarded, fail-closed taxonomy,
stdlib-only, ``sha256:`` digest pins over type-tagged canonical
payloads, ``audit.ndjson/1`` events.

Honest boundary: this module books *policy decisions* consistently
(rule vocabulary is pinned so policy drift is detectable; decisions
are reproducible and sealed). It performs no actual content
inspection — categories and signals are host-reported (GIGO). A
"remove" decision is a record, not an act; production still needs a
real classifier, human review queues, and an execution path.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from dataclasses import dataclass
from typing import Any, Mapping

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
TRUST_SAFETY_VERSION = "trust-safety.v1"

#: Schema pin carried by records and audit events.
TRUST_SAFETY_SCHEMA = "northstar.trust-safety.v1"

#: Schema pin for audit.ndjson records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned enforcement categories (policy drift detectable).
CATEGORIES = (
    "harassment",
    "hate",
    "violence",
    "self_harm",
    "sexual",
    "spam",
    "misinformation",
    "copyright",
    "privacy_violation",
    "regulated_goods",
)

#: Pinned enforcement actions, ordered by severity.
ACTIONS = ("allow", "rate_limit", "review", "restrict", "remove", "escalate")

#: Pinned verdicts emitted by enforce().
VERDICTS = ("allowed", "limited", "flagged", "restricted", "removed", "escalated")

#: Pinned audit kinds.
_KINDS = (
    "policy-defined",
    "policy-disabled",
    "enforced",
    "rejected",
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class TrustSafetyError(Exception):
    """Base error for the trust & safety policy engine."""


class UnknownPolicyError(TrustSafetyError):
    """No such policy id."""


class UnknownCategoryError(TrustSafetyError):
    """Category not in the pinned vocabulary."""


class UnknownActionError(TrustSafetyError):
    """Action not in the pinned vocabulary."""


class BadPolicyError(TrustSafetyError):
    """Malformed policy definition (duplicate rule, bad shape, ...)."""


class DisabledPolicyError(TrustSafetyError):
    """Policy exists but is disabled — enforcement refuses."""


class SeqOrderError(TrustSafetyError):
    """Mutation seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TrustSafetyError(f"{field_name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TrustSafetyError(f"{field_name} must be a non-empty string")
    return value


def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore
    import json

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) >= 2**53:
                raise TrustSafetyError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise TrustSafetyError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise TrustSafetyError(f"unencodable type: {type(v).__name__}")

    return json.dumps(
        _tag(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _pin(payload: Any, seed: str = "") -> str:
    return "sha256:" + hmac.new(
        seed.encode("utf-8"), _canonical(payload), hashlib.sha256
    ).hexdigest()


def _action_verdict(action: str) -> str:
    return {
        "allow": "allowed",
        "rate_limit": "limited",
        "review": "flagged",
        "restrict": "restricted",
        "remove": "removed",
        "escalate": "escalated",
    }[action]


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    """A single pinned rule: category -> action."""

    rule_id: str
    category: str
    action: str
    description: str = ""
    digest: str = ""

    def __post_init__(self) -> None:
        _check_nonempty_str(self.rule_id, "rule_id")
        if self.category not in CATEGORIES:
            raise UnknownCategoryError(f"unknown category: {self.category!r}")
        if self.action not in ACTIONS:
            raise UnknownActionError(f"unknown action: {self.action!r}")
        expected = _pin(
            ("rule", self.rule_id, self.category, self.action, self.description)
        )
        if self.digest and self.digest != expected:
            raise TrustSafetyError("rule digest mismatch")
        if not self.digest:
            object.__setattr__(self, "digest", expected)

    def verify(self) -> bool:
        return self.digest == _pin(
            ("rule", self.rule_id, self.category, self.action, self.description)
        )


@dataclass(frozen=True)
class PolicyRecord:
    """A pinned, digest-sealed policy definition."""

    policy_id: str
    name: str
    seq: int
    rules: tuple
    enabled: bool = True
    digest: str = ""

    def __post_init__(self) -> None:
        _check_nonempty_str(self.policy_id, "policy_id")
        _check_nonempty_str(self.name, "name")
        _check_seq(self.seq)
        if not self.rules:
            raise BadPolicyError("policy must define at least one rule")
        seen: set[str] = set()
        for r in self.rules:
            if not isinstance(r, Rule):
                raise BadPolicyError("rules must be Rule records")
            if r.rule_id in seen:
                raise BadPolicyError(f"duplicate rule id: {r.rule_id!r}")
            seen.add(r.rule_id)
        expected = _pin(
            (
                "policy",
                self.policy_id,
                self.name,
                tuple(sorted(seen)),
                self.enabled,
                [r.digest for r in sorted(self.rules, key=lambda x: x.rule_id)],
            )
        )
        if self.digest and self.digest != expected:
            raise TrustSafetyError("policy digest mismatch")
        if not self.digest:
            object.__setattr__(self, "digest", expected)

    def verify(self) -> bool:
        return self.digest == _pin(
            (
                "policy",
                self.policy_id,
                self.name,
                tuple(sorted(r.rule_id for r in self.rules)),
                self.enabled,
                [r.digest for r in sorted(self.rules, key=lambda x: x.rule_id)],
            )
        )


@dataclass(frozen=True)
class Decision:
    """A sealed enforcement decision (verdicts are data, never raised)."""

    decision_id: str
    policy_id: str
    seq: int
    subject_ref: str
    category: str
    action: str
    verdict: str
    rule_id: str
    reason: str = ""
    digest: str = ""

    def __post_init__(self) -> None:
        _check_nonempty_str(self.decision_id, "decision_id")
        _check_nonempty_str(self.policy_id, "policy_id")
        _check_seq(self.seq)
        _check_nonempty_str(self.subject_ref, "subject_ref")
        if self.category not in CATEGORIES:
            raise UnknownCategoryError(f"unknown category: {self.category!r}")
        if self.action not in ACTIONS:
            raise UnknownActionError(f"unknown action: {self.action!r}")
        if self.verdict not in VERDICTS:
            raise TrustSafetyError(f"unknown verdict: {self.verdict!r}")
        expected = _pin(
            (
                "decision",
                self.decision_id,
                self.policy_id,
                self.subject_ref,
                self.category,
                self.action,
                self.verdict,
                self.rule_id,
                self.reason,
            )
        )
        if self.digest and self.digest != expected:
            raise TrustSafetyError("decision digest mismatch")
        if not self.digest:
            object.__setattr__(self, "digest", expected)

    def verify(self) -> bool:
        return self.digest == _pin(
            (
                "decision",
                self.decision_id,
                self.policy_id,
                self.subject_ref,
                self.category,
                self.action,
                self.verdict,
                self.rule_id,
                self.reason,
            )
        )


@dataclass(frozen=True)
class AuditSummary:
    """A digest-pinned summary of enforcement activity."""

    seq: int
    policy_count: int
    decision_count: int
    verdict_counts: tuple
    state_digest: str
    digest: str = ""

    def __post_init__(self) -> None:
        _check_seq(self.seq)
        expected = _pin(
            (
                "audit-summary",
                self.policy_count,
                self.decision_count,
                self.verdict_counts,
                self.state_digest,
            )
        )
        if self.digest and self.digest != expected:
            raise TrustSafetyError("audit summary digest mismatch")
        if not self.digest:
            object.__setattr__(self, "digest", expected)

    def verify(self) -> bool:
        return self.digest == _pin(
            (
                "audit-summary",
                self.policy_count,
                self.decision_count,
                self.verdict_counts,
                self.state_digest,
            )
        )


# ---------------------------------------------------------------------------
# Audit event helper
# ---------------------------------------------------------------------------


def trust_safety_audit_event(kind: str, seq: int, **detail: Any) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the policy engine."""
    if kind not in _KINDS:
        raise TrustSafetyError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "trust_safety",
        "module_version": TRUST_SAFETY_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# TrustSafety
# ---------------------------------------------------------------------------


class TrustSafety:
    """Deterministic trust & safety policy engine.

    Policies are pinned rule sets over a fixed category/action
    vocabulary. :meth:`enforce` is a pure decision function: given a
    policy, a subject reference, a host-reported category and optional
    host-reported signals, it returns a sealed :class:`Decision`
    (verdicts are data — ``remove`` is a record, never an act).
    """

    def __init__(self, seed: str = "") -> None:
        self._lock = threading.RLock()
        self._seed = seed
        self._last_seq = -1
        self._policies: dict[str, PolicyRecord] = {}
        self._decisions: dict[str, Decision] = {}
        self._decision_ids: list[str] = []
        self._counter = 0
        self._events: list[Mapping[str, Any]] = []

    # -- internal ------------------------------------------------------

    def _next_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})"
            )
        self._last_seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._events.append(trust_safety_audit_event(kind, seq, **detail))

    # -- policy --------------------------------------------------------

    def policy(
        self,
        policy_id: str,
        seq: int,
        name: str,
        rules: list[Mapping[str, str]],
    ) -> PolicyRecord:
        """Define (or redefine) a policy with a pinned rule set.

        ``rules`` is a list of ``{"rule_id", "category", "action",
        "description"?}`` mappings. Redefining an existing policy id
        replaces it (new digest, new seq); use :meth:`disable` to
        retire one.
        """
        _check_nonempty_str(policy_id, "policy_id")
        _check_nonempty_str(name, "name")
        if not isinstance(rules, list):
            raise BadPolicyError("rules must be a list of mappings")
        with self._lock:
            self._next_seq(seq)  # failed mutations consume their seq
            rule_objs = []
            for r in rules:
                if not isinstance(r, Mapping):
                    raise BadPolicyError("each rule must be a mapping")
                rule_objs.append(
                    Rule(
                        rule_id=str(r.get("rule_id", "")),
                        category=str(r.get("category", "")),
                        action=str(r.get("action", "")),
                        description=str(r.get("description", "")),
                    )
                )
            record = PolicyRecord(
                policy_id=policy_id, name=name, seq=seq, rules=tuple(rule_objs)
            )
            self._policies[policy_id] = record
            self._emit(
                "policy-defined",
                seq,
                policy_id=policy_id,
                rule_count=len(rule_objs),
                digest=record.digest,
            )
            return record

    def disable(self, policy_id: str, seq: int) -> PolicyRecord:
        """Retire a policy: it stays readable but refuses enforcement."""
        with self._lock:
            self._next_seq(seq)
            record = self._policies.get(policy_id)
            if record is None:
                raise UnknownPolicyError(f"unknown policy: {policy_id!r}")
            disabled = PolicyRecord(
                policy_id=record.policy_id,
                name=record.name,
                seq=seq,
                rules=record.rules,
                enabled=False,
            )
            self._policies[policy_id] = disabled
            self._emit("policy-disabled", seq, policy_id=policy_id)
            return disabled

    def get_policy(self, policy_id: str) -> PolicyRecord:
        record = self._policies.get(policy_id)
        if record is None:
            raise UnknownPolicyError(f"unknown policy: {policy_id!r}")
        return record

    def policy_ids(self) -> tuple:
        return tuple(sorted(self._policies))

    # -- enforcement ---------------------------------------------------

    def enforce(
        self,
        policy_id: str,
        seq: int,
        subject_ref: str,
        category: str,
        signals: Mapping[str, Any] | None = None,
        reason: str = "",
    ) -> Decision:
        """Return a sealed enforcement decision for a subject.

        The first rule (in rule-id order) matching ``category`` wins;
        an unmatched category is ``allow``/``allowed`` as data. A
        disabled or unknown policy raises (fail-closed) — the caller
        must pick an enabled policy.
        """
        with self._lock:
            self._next_seq(seq)
            record = self._policies.get(policy_id)
            if record is None:
                self._emit("rejected", seq, op="enforce", reason="unknown-policy")
                raise UnknownPolicyError(f"unknown policy: {policy_id!r}")
            if not record.enabled:
                self._emit("rejected", seq, op="enforce", reason="disabled-policy")
                raise DisabledPolicyError(f"policy disabled: {policy_id!r}")
            _check_nonempty_str(subject_ref, "subject_ref")
            if category not in CATEGORIES:
                self._emit("rejected", seq, op="enforce", reason="unknown-category")
                raise UnknownCategoryError(f"unknown category: {category!r}")
            matched: Rule | None = None
            for rule in sorted(record.rules, key=lambda r: r.rule_id):
                if rule.category == category:
                    matched = rule
                    break
            action = matched.action if matched else "allow"
            self._counter += 1
            decision = Decision(
                decision_id=f"dec-{self._counter}",
                policy_id=policy_id,
                seq=seq,
                subject_ref=subject_ref,
                category=category,
                action=action,
                verdict=_action_verdict(action),
                rule_id=matched.rule_id if matched else "",
                reason=reason,
            )
            self._decisions[decision.decision_id] = decision
            self._decision_ids.append(decision.decision_id)
            self._emit(
                "enforced",
                seq,
                decision_id=decision.decision_id,
                policy_id=policy_id,
                verdict=decision.verdict,
                digest=decision.digest,
            )
            return decision

    def get_decision(self, decision_id: str) -> Decision:
        decision = self._decisions.get(decision_id)
        if decision is None:
            raise TrustSafetyError(f"unknown decision: {decision_id!r}")
        return decision

    def decision_ids(self) -> tuple:
        return tuple(self._decision_ids)

    # -- audit ---------------------------------------------------------

    def audit(self, seq: int) -> AuditSummary:
        """Return a digest-pinned summary of policies and decisions."""
        seq = _check_seq(seq)
        with self._lock:
            verdict_counts: dict[str, int] = {v: 0 for v in VERDICTS}
            digests = []
            for did in self._decision_ids:
                d = self._decisions[did]
                verdict_counts[d.verdict] += 1
                digests.append(d.digest)
            counts = tuple(sorted(verdict_counts.items()))
            state_digest = _pin(
                (
                    "ts-state",
                    tuple(sorted(p.digest for p in self._policies.values())),
                    tuple(digests),
                ),
                self._seed,
            )
            return AuditSummary(
                seq=seq,
                policy_count=len(self._policies),
                decision_count=len(self._decision_ids),
                verdict_counts=counts,
                state_digest=state_digest,
            )

    def audit_log(self) -> tuple:
        return tuple(self._events)


def main() -> None:
    ts = TrustSafety()
    pol = ts.policy(
        "p1",
        1,
        "community-standards",
        [
            {"rule_id": "r1", "category": "spam", "action": "rate_limit"},
            {"rule_id": "r2", "category": "hate", "action": "remove"},
        ],
    )
    assert pol.verify()
    d1 = ts.enforce("p1", 2, "post-1", "spam", reason="host-reported")
    assert d1.verdict == "limited" and d1.verify()
    d2 = ts.enforce("p1", 3, "post-2", "hate")
    assert d2.verdict == "removed" and d2.verify()
    d3 = ts.enforce("p1", 4, "post-3", "harassment")  # unmatched -> allow
    assert d3.verdict == "allowed"
    summary = ts.audit(5)
    assert summary.verify() and summary.decision_count == 3
    print("trust-safety OK: policy, enforce, unmatched-allow, audit")


if __name__ == "__main__":
    main()
