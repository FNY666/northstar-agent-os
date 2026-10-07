"""Probe flywheel feeding plan defense: repeated failures become plan rules.

P0 production wiring: the probe flywheel (``probe_flywheel``) turns repeated
production failures into ``expected: "deny"`` probes. Plan defense
(``plan_defense``) refuses dangerous plans at execution time. This module
closes the loop between them: every time the flywheel emits a *new* probe
(a failure pattern crossing ``PROBE_THRESHOLD``), the loop translates it
into a frozen :class:`DefenseRule` that the plan check enforces.

The direction of the flow is one-way and mechanical:

* **Flywheel -> defense.** ``record_failure`` folds the bundle into the
  flywheel. If new probes were emitted, one defense rule per probe is
  created. No probe, no rule.
* **Defense check.** ``check`` runs the base ``PlanDefense.check`` and, in
  addition, scans the plan's subgoals for the failed-action shape. A
  subgoal whose tokens overlap the failed action's tokens is flagged with
  the ``probe-blocked`` issue.
* **Remediation lifts the rule.** ``remediate`` removes a rule once the
  host fixed the underlying cause. The flywheel counts failures; the host
  owns remediation.

Rule matching is lexical: the failed ``action_type`` (e.g. ``"db.delete"``)
is tokenized into lowercase alphanumeric words (``{"db", "delete"}``) and a
subgoal is blocked when its id or description shares at least one token.
This is deliberately the same honesty level as ``detect_scope_drift``'s
keyword heuristic — a flag for refusal-and-review, never proof of malice.

Honest scope:

* The loop cannot know *why* the action kept failing; the rule refuses the
  shape, the host diagnoses the cause.
* Token overlap is noisy: an unrelated subgoal mentioning ``"delete"``
  while ``"db.delete"`` failed with ``"permission-denied"`` is still
  blocked. That is the documented cost of a deny-shape probe.
* The base plan-defense detectors keep working unchanged; learned rules
  are additive only.
* No wall-clock anywhere: all sequence numbers are caller-supplied ints,
  the same discipline as both composed modules.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

try:  # sibling imports when the package is installed
    from probe_flywheel import (
        Flywheel,
        FailurePattern,
        PROBE_FLYWHEEL_VERSION,
        PROBE_THRESHOLD,
    )
    from plan_defense import (
        PlanDefense,
        DefenseReport,
        PLAN_DEFENSE_VERSION,
        STALE_PLAN_THRESHOLD,
        SCOPE_DRIFT_THRESHOLD,
        ISSUE_STALE_PLAN,
        ISSUE_PLAN_INJECTION,
        ISSUE_SCOPE_DRIFT,
    )
except Exception:  # pragma: no cover - standalone import must keep working
    Flywheel = None  # type: ignore[assignment]
    FailurePattern = None  # type: ignore[assignment]
    PROBE_FLYWHEEL_VERSION = None  # type: ignore[assignment]
    PROBE_THRESHOLD = None  # type: ignore[assignment]
    PlanDefense = None  # type: ignore[assignment]
    DefenseReport = None  # type: ignore[assignment]
    PLAN_DEFENSE_VERSION = None  # type: ignore[assignment]
    STALE_PLAN_THRESHOLD = None  # type: ignore[assignment]
    SCOPE_DRIFT_THRESHOLD = None  # type: ignore[assignment]
    ISSUE_STALE_PLAN = None  # type: ignore[assignment]
    ISSUE_PLAN_INJECTION = None  # type: ignore[assignment]
    ISSUE_SCOPE_DRIFT = None  # type: ignore[assignment]

#: Version of the probe->defense wiring described here.
PROBE_DEFENSE_COMBO_VERSION = "probe-defense-combo.v1"

#: Schema pin stamped on rules and reports.
SCHEMA_PIN = "northstar.probe-defense-combo.v1"

#: Issue appended to the base plan-defense vocabulary when a learned
#: rule blocks one or more subgoals. Fixed vocabulary, fixed position
#: (after the three base issues).
ISSUE_PROBE_BLOCKED = "probe-blocked"

_WORD_RE = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> frozenset[str]:
    """Lowercase alphanumeric word tokens of ``text``."""
    if not isinstance(text, str):
        return frozenset()
    return frozenset(_WORD_RE.findall(text.lower()))


def _check_seq(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty str")
    return value


def _require_siblings() -> None:
    if Flywheel is None or PlanDefense is None:
        raise RuntimeError(
            "probe_defense_combo requires the sibling modules "
            "probe_flywheel and plan_defense"
        )


@dataclass(frozen=True)
class DefenseRule:
    """One learned plan-defense rule, derived from a flywheel probe.

    ``rule_id`` is the deterministic probe name (``failure-flywheel-…``).
    ``action_tokens`` is the tokenized failed action type used for the
    lexical subgoal match. ``created_seq`` is the ``last_seen_seq`` of the
    pattern at the moment the rule was created.
    """

    rule_id: str
    action_type: str
    error_type: str
    probe_name: str
    action_tokens: frozenset[str] = field(compare=False)
    created_seq: int = 0
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _check_nonempty_str(self.rule_id, "rule_id")
        _check_nonempty_str(self.action_type, "action_type")
        _check_nonempty_str(self.error_type, "error_type")
        _check_nonempty_str(self.probe_name, "probe_name")
        if not isinstance(self.action_tokens, frozenset) or not self.action_tokens:
            raise ValueError("action_tokens must be a non-empty frozenset")
        _check_seq(self.created_seq, "created_seq")

    def matches_subgoal(self, subgoal_id: str, description: str = "") -> tuple[str, ...]:
        """Tokens shared with the failed action, in sorted order.

        Empty tuple means no match. Never raises on malformed input —
        a subgoal the matcher cannot read is simply not matched.
        """
        shared = self.action_tokens & (_tokens(subgoal_id) | _tokens(description))
        return tuple(sorted(shared))

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "rule_id": self.rule_id,
            "action_type": self.action_type,
            "error_type": self.error_type,
            "probe_name": self.probe_name,
            "action_tokens": sorted(self.action_tokens),
            "created_seq": self.created_seq,
        }


@dataclass(frozen=True)
class RuleHit:
    """One subgoal blocked by one learned rule."""

    rule_id: str
    subgoal_id: str
    matched_tokens: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "subgoal_id": self.subgoal_id,
            "matched_tokens": list(self.matched_tokens),
        }


@dataclass(frozen=True)
class IngestionReport:
    """Outcome of :meth:`ProbeDefenseLoop.record_failure`."""

    pattern: Any  # FailurePattern
    new_rules: tuple[DefenseRule, ...]
    total_rules: int
    combo_version: str = PROBE_DEFENSE_COMBO_VERSION

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "combo_version": self.combo_version,
            "pattern": self.pattern.as_dict(),
            "new_rules": [r.as_dict() for r in self.new_rules],
            "total_rules": self.total_rules,
        }


@dataclass(frozen=True)
class LoopReport:
    """Outcome of :meth:`ProbeDefenseLoop.check_report`. Frozen, auditable."""

    clean: bool
    issues: tuple[str, ...]
    base_issues: tuple[str, ...]
    rule_hits: tuple[RuleHit, ...]
    combo_version: str = PROBE_DEFENSE_COMBO_VERSION

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "combo_version": self.combo_version,
            "clean": self.clean,
            "issues": list(self.issues),
            "base_issues": list(self.base_issues),
            "rule_hits": [h.as_dict() for h in self.rule_hits],
        }


class ProbeDefenseLoop:
    """Flywheel probes feed plan defense automatically.

    Usage::

        loop = ProbeDefenseLoop(trusted_subgoal_ids={"a", "b"})
        report = loop.record_failure(
            {"failed_action": "db.delete",
             "error": "permission-denied", "created_seq": 7})
        # after 3 such failures a DefenseRule exists; plans with a
        # subgoal shaped like "db.delete" are flagged "probe-blocked"
        verdict = loop.check(plan, "goal text", current_state_seq=50,
                             plan_created_seq=10)
    """

    def __init__(
        self,
        trusted_subgoal_ids: Iterable[str] | None = None,
        stale_threshold: int | None = None,
        drift_threshold: float | None = None,
    ) -> None:
        _require_siblings()
        self._flywheel = Flywheel()
        self._stale_threshold = (
            STALE_PLAN_THRESHOLD if stale_threshold is None else stale_threshold
        )
        self._drift_threshold = (
            SCOPE_DRIFT_THRESHOLD if drift_threshold is None else drift_threshold
        )
        self._trusted: frozenset[str] | None = (
            None
            if trusted_subgoal_ids is None
            else frozenset(trusted_subgoal_ids)
        )
        self._defense = self._build_defense()
        # rule_id -> DefenseRule, insertion order (deterministic)
        self._rules: dict[str, DefenseRule] = {}

    # -- construction helpers -----------------------------------------

    def _build_defense(self) -> Any:
        trusted = None if self._trusted is None else set(self._trusted)
        return PlanDefense(
            trusted_subgoal_ids=trusted,
            stale_threshold=self._stale_threshold,
            drift_threshold=self._drift_threshold,
        )

    @staticmethod
    def _rule_for(pattern: Any) -> DefenseRule:
        return DefenseRule(
            rule_id=pattern.probe_name(),
            action_type=pattern.action_type,
            error_type=pattern.error_type,
            probe_name=pattern.probe_name(),
            action_tokens=frozenset(_tokens(pattern.action_type)),
            created_seq=pattern.last_seen_seq,
        )

    # -- properties ----------------------------------------------------

    @property
    def flywheel(self) -> Any:
        return self._flywheel

    @property
    def defense(self) -> Any:
        return self._defense

    @property
    def rules(self) -> tuple[DefenseRule, ...]:
        """Learned rules in creation order."""
        return tuple(self._rules.values())

    # -- failure ingestion ---------------------------------------------

    def record_failure(self, bundle: Any) -> IngestionReport:
        """Fold one failure into the flywheel; create rules for new probes.

        Returns an :class:`IngestionReport` with the updated pattern and
        any rules created by this call. Malformed bundles raise
        ``ValueError`` from the flywheel — fail-closed, nothing is half
        recorded.
        """
        known_before = set(self._flywheel.probe_names())
        pattern = self._flywheel.record_failure(bundle)
        # One call folds exactly one bundle into exactly one pattern, so a
        # new probe can only belong to this pattern.
        new_rules: list[DefenseRule] = []
        if pattern.probe_ready():
            rule_id = pattern.probe_name()
            if rule_id not in known_before and rule_id not in self._rules:
                rule = self._rule_for(pattern)
                self._rules[rule_id] = rule
                new_rules.append(rule)
        return IngestionReport(
            pattern=pattern,
            new_rules=tuple(new_rules),
            total_rules=len(self._rules),
        )

    def record_failures(self, bundles: Iterable[Any]) -> tuple[IngestionReport, ...]:
        """Fold many failures; fail-closed on the first malformed bundle."""
        return tuple(self.record_failure(b) for b in bundles)

    # -- trusted set management -----------------------------------------

    def set_trusted_subgoal_ids(self, trusted_subgoal_ids: Iterable[str] | None) -> None:
        """Replace the trusted subgoal set; rebuilds the inner defense."""
        self._trusted = (
            None
            if trusted_subgoal_ids is None
            else frozenset(trusted_subgoal_ids)
        )
        self._defense = self._build_defense()

    # -- remediation ------------------------------------------------------

    def remediate(self, rule_id: str) -> DefenseRule:
        """Lift a learned rule after the host remediated the cause.

        Returns the removed rule. Raises ``KeyError`` for an unknown
        rule id — remediation must name a rule that exists.
        """
        _check_nonempty_str(rule_id, "rule_id")
        try:
            return self._rules.pop(rule_id)
        except KeyError:
            raise KeyError(f"unknown defense rule: {rule_id}") from None

    # -- plan checking -----------------------------------------------------

    @staticmethod
    def _subgoals(plan: Any) -> tuple[tuple[str, str], ...]:
        """Extract (id, description) pairs; malformed plan -> empty tuple."""
        if not isinstance(plan, Mapping):
            return ()
        subgoals = plan.get("subgoals")
        if not isinstance(subgoals, (list, tuple)):
            return ()
        pairs: list[tuple[str, str]] = []
        for sg in subgoals:
            if not isinstance(sg, Mapping):
                return ()
            sid = sg.get("id")
            if not isinstance(sid, str) or not sid:
                return ()
            desc = sg.get("description", "")
            if not isinstance(desc, str):
                return ()
            pairs.append((sid, desc))
        return tuple(pairs)

    def _scan_rules(self, plan: Any) -> tuple[RuleHit, ...]:
        hits: list[RuleHit] = []
        for sid, desc in self._subgoals(plan):
            for rule in self._rules.values():
                matched = rule.matches_subgoal(sid, desc)
                if matched:
                    hits.append(
                        RuleHit(
                            rule_id=rule.rule_id,
                            subgoal_id=sid,
                            matched_tokens=matched,
                        )
                    )
        return tuple(hits)

    def check(
        self,
        plan: Mapping,
        original_goal: str,
        current_state_seq: int,
        plan_created_seq: int,
    ) -> str | list[str]:
        """Run base plan defense plus learned probe rules.

        Returns ``"clean"`` or the issue list: base issues in their fixed
        order, then ``probe-blocked`` when any learned rule hit.
        """
        report = self.check_report(
            plan, original_goal, current_state_seq, plan_created_seq
        )
        return "clean" if report.clean else list(report.issues)

    def check_report(
        self,
        plan: Mapping,
        original_goal: str,
        current_state_seq: int,
        plan_created_seq: int,
    ) -> LoopReport:
        """Same as :meth:`check` but returns a frozen :class:`LoopReport`."""
        base = self._defense.check(
            plan, original_goal, current_state_seq, plan_created_seq
        )
        base_issues: tuple[str, ...] = () if base == "clean" else tuple(base)
        hits = self._scan_rules(plan)
        issues = list(base_issues)
        if hits and ISSUE_PROBE_BLOCKED not in issues:
            issues.append(ISSUE_PROBE_BLOCKED)
        return LoopReport(
            clean=not issues,
            issues=tuple(issues),
            base_issues=base_issues,
            rule_hits=hits,
        )


def main() -> None:
    _require_siblings()
    loop = ProbeDefenseLoop(trusted_subgoal_ids={"a", "b"})
    for seq in range(1, PROBE_THRESHOLD + 1):
        rep = loop.record_failure(
            {
                "failed_action": "db.delete",
                "error": "permission-denied",
                "created_seq": seq,
            }
        )
    assert rep.total_rules == 1, rep.as_dict()
    assert len(rep.new_rules) == 1

    plan = {
        "subgoals": [
            {"id": "a", "description": "fetch user profile data"},
            {"id": "db-delete-rows", "description": "delete stale rows from db"},
        ]
    }
    # 'a' is trusted but 'db-delete-rows' is not -> injection + probe-blocked
    verdict = loop.check(plan, "fetch user profile", 50, 10)
    assert ISSUE_PLAN_INJECTION in verdict, verdict
    assert ISSUE_PROBE_BLOCKED in verdict, verdict

    loop.set_trusted_subgoal_ids({"a", "db-delete-rows"})
    verdict = loop.check(plan, "fetch user profile", 50, 10)
    assert verdict == [ISSUE_PROBE_BLOCKED], verdict

    rule_id = loop.rules[0].rule_id
    loop.remediate(rule_id)
    assert loop.check(plan, "fetch user profile", 50, 10) == "clean"

    print(
        f"probe-defense-combo OK: {rep.total_rules} rule(s) learned, "
        "blocked, then lifted after remediation"
    )


if __name__ == "__main__":
    main()
