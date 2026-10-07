"""Plan defense: stale-plan detection, plan-injection defense, scope-drift detection.

A plan that passed the structural gates (see ``planner_gates``) can still be
dangerous at *execution* time for three temporal/content reasons:

* **Stale plan** — the plan was built against old state. If the world moved
  on by more than ``STALE_PLAN_THRESHOLD`` sequence ticks since the plan
  was created, the plan's assumptions are untrustworthy and it must be
  re-planned, not executed.
* **Plan injection** — a subgoal the planner never proposed got into the
  plan (prompt injection, tool-output smuggling, a compromised sub-agent).
  Any subgoal id outside the trusted set is an injection, full stop.
* **Scope drift** — the plan gradually expands beyond the original goal.
  Measured as keyword overlap between the goal and the subgoal
  descriptions: below ``SCOPE_DRIFT_THRESHOLD`` the plan is no longer
  *about* the goal it was authorized for.

All three are fail-closed detectors. A plan the defense cannot even parse
is not "clean" — it is rejected. No wall-clock anywhere: staleness is
measured in caller-supplied integer sequence ticks, the same discipline as
the rest of the runtime.

Honest scope: these are *detectors*, not a defense-in-depth story on their
own. ``detect_plan_injection`` trusts the caller-supplied trusted set —
provenance of that set is the caller's job. ``detect_scope_drift`` is a
lexical heuristic (keyword overlap), not a semantic judgment: a plan can
drift in meaning while keeping the same words, and a legitimate plan can
use synonyms. Treat drift as a *flag for re-review*, never as proof of
malice. None of this stops an attacker who controls the state sequence
numbers — sequence integrity is the host's job.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

#: A plan older than this many sequence ticks is stale and must be
#: re-planned before execution.
STALE_PLAN_THRESHOLD = 100

#: Minimum fraction of the goal's keywords that must appear across the
#: subgoal descriptions. Below this, the plan is judged to have drifted
#: away from its authorized goal.
SCOPE_DRIFT_THRESHOLD = 0.5

#: Version pin for the defense vocabulary and thresholds.
PLAN_DEFENSE_VERSION = "plan-defense.v1"

#: Fixed issue vocabulary returned by :class:`PlanDefense.check`.
ISSUE_STALE_PLAN = "stale-plan"
ISSUE_PLAN_INJECTION = "plan-injection"
ISSUE_SCOPE_DRIFT = "scope-drift"

_WORD_RE = re.compile(r"[a-z0-9]+")


class PlanDefenseError(ValueError):
    """Base class for plan-defense input errors. Never raised directly."""


class MalformedPlan(PlanDefenseError):
    """The plan is not shaped the way the detectors require."""


def _validate_seq(value: object, name: str) -> int:
    """Validate a caller-supplied sequence number. Rejects bools/negatives."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise PlanDefenseError(f"{name} must be an integer sequence number")
    if value < 0:
        raise PlanDefenseError(f"{name} must be non-negative")
    return value


def _subgoal_ids(plan: Mapping) -> tuple[str, ...]:
    """Extract subgoal ids from a plan mapping. Raises MalformedPlan."""
    if not isinstance(plan, Mapping):
        raise MalformedPlan("plan must be a mapping with a 'subgoals' sequence")
    subgoals = plan.get("subgoals")
    if subgoals is None:
        raise MalformedPlan("plan is missing 'subgoals'")
    if not isinstance(subgoals, Sequence) or isinstance(subgoals, (str, bytes)):
        raise MalformedPlan("plan['subgoals'] must be a sequence of subgoal mappings")
    ids: list[str] = []
    for sg in subgoals:
        if not isinstance(sg, Mapping):
            raise MalformedPlan("each subgoal must be a mapping with an 'id'")
        sid = sg.get("id")
        if not isinstance(sid, str) or not sid:
            raise MalformedPlan("each subgoal must carry a non-empty string 'id'")
        ids.append(sid)
    return tuple(ids)


def _subgoal_descriptions(plan: Mapping) -> tuple[str, ...]:
    """Extract subgoal descriptions; missing descriptions count as empty."""
    ids_checked = _subgoal_ids(plan)  # validates shape first
    descs: list[str] = []
    for sg in plan["subgoals"]:
        desc = sg.get("description", "")
        if not isinstance(desc, str):
            raise MalformedPlan("subgoal 'description' must be a string")
        descs.append(desc)
    return tuple(descs)


def detect_stale_plan(plan: Mapping, current_state_seq: int, plan_created_seq: int) -> bool:
    """True when the plan is stale relative to current state.

    Stale means the state advanced more than ``STALE_PLAN_THRESHOLD`` ticks
    since the plan was created — or the plan claims to come from the future
    (``plan_created_seq > current_state_seq``), which is treated as stale
    fail-closed rather than trusted.
    """
    _subgoal_ids(plan)  # shape-check; a malformed plan is not "fresh"
    current_state_seq = _validate_seq(current_state_seq, "current_state_seq")
    plan_created_seq = _validate_seq(plan_created_seq, "plan_created_seq")
    if plan_created_seq > current_state_seq:
        return True
    return (current_state_seq - plan_created_seq) > STALE_PLAN_THRESHOLD


def detect_plan_injection(plan: Mapping, trusted_subgoal_ids: Iterable[str]) -> bool:
    """True when the plan contains a subgoal outside the trusted set.

    The trusted set is the ids the planner actually proposed (e.g. the ids
    that passed ``planner_gates.propose_plan``). Anything else in the plan
    is an injection — it does not matter how it got there.
    """
    ids = _subgoal_ids(plan)
    if trusted_subgoal_ids is None:
        raise PlanDefenseError("trusted_subgoal_ids must be an iterable of strings")
    trusted: set[str] = set()
    for tid in trusted_subgoal_ids:
        if not isinstance(tid, str) or not tid:
            raise PlanDefenseError("trusted_subgoal_ids must contain non-empty strings")
        trusted.add(tid)
    return any(sid not in trusted for sid in ids)


def _keywords(text: str) -> frozenset[str]:
    """Lowercase alphanumeric word tokens of a text."""
    return frozenset(_WORD_RE.findall(text.lower()))


def detect_scope_drift(original_goal: str, current_subgoals: Sequence[Mapping]) -> bool:
    """True when the subgoals no longer address the original goal.

    Overlap is the fraction of the goal's keywords that appear in at least
    one subgoal description. Below ``SCOPE_DRIFT_THRESHOLD`` the plan has
    drifted. Fail-closed edges: an empty goal (no keywords to anchor on)
    and an empty subgoal list both count as drift.
    """
    if not isinstance(original_goal, str):
        raise PlanDefenseError("original_goal must be a string")
    if current_subgoals is None:
        raise PlanDefenseError("current_subgoals must be a sequence of subgoal mappings")
    if not isinstance(current_subgoals, Sequence) or isinstance(current_subgoals, (str, bytes)):
        raise PlanDefenseError("current_subgoals must be a sequence of subgoal mappings")
    goal_kw = _keywords(original_goal)
    if not goal_kw:
        return True
    subgoal_kw: set[str] = set()
    for sg in current_subgoals:
        if not isinstance(sg, Mapping):
            raise PlanDefenseError("each subgoal must be a mapping")
        desc = sg.get("description", "")
        if not isinstance(desc, str):
            raise PlanDefenseError("subgoal 'description' must be a string")
        subgoal_kw |= _keywords(desc)
    if not subgoal_kw:
        return True
    overlap = len(goal_kw & subgoal_kw) / len(goal_kw)
    return overlap < SCOPE_DRIFT_THRESHOLD


@dataclass(frozen=True)
class DefenseReport:
    """Outcome of :meth:`PlanDefense.check`. Frozen and auditable."""

    clean: bool
    issues: tuple[str, ...]
    defense_version: str = PLAN_DEFENSE_VERSION

    def as_dict(self) -> dict:
        return {
            "clean": self.clean,
            "issues": list(self.issues),
            "defense_version": self.defense_version,
        }


class PlanDefense:
    """Combines the three plan defenses into one execution-time check.

    Usage::

        defense = PlanDefense(trusted_subgoal_ids={"a", "b"})
        report = defense.check(plan, original_goal, current_state_seq,
                               plan_created_seq)
        if not report.clean:
            # re-plan / escalate; never execute a flagged plan

    Returns ``"clean"`` when all three detectors pass, otherwise the list
    of issue strings from the fixed vocabulary (``stale-plan``,
    ``plan-injection``, ``scope-drift``), in fixed order.
    """

    def __init__(
        self,
        trusted_subgoal_ids: Iterable[str] | None = None,
        stale_threshold: int = STALE_PLAN_THRESHOLD,
        drift_threshold: float = SCOPE_DRIFT_THRESHOLD,
    ) -> None:
        self._trusted: frozenset[str] | None
        if trusted_subgoal_ids is None:
            self._trusted = None
        else:
            trusted_set: set[str] = set()
            for tid in trusted_subgoal_ids:
                if not isinstance(tid, str) or not tid:
                    raise PlanDefenseError("trusted_subgoal_ids must contain non-empty strings")
                trusted_set.add(tid)
            self._trusted = frozenset(trusted_set)
        if isinstance(stale_threshold, bool) or not isinstance(stale_threshold, int) or stale_threshold < 0:
            raise PlanDefenseError("stale_threshold must be a non-negative integer")
        if isinstance(drift_threshold, bool) or not isinstance(drift_threshold, (int, float)):
            raise PlanDefenseError("drift_threshold must be a number")
        if not 0 < drift_threshold <= 1:
            raise PlanDefenseError("drift_threshold must be in (0, 1]")
        self._stale_threshold = stale_threshold
        self._drift_threshold = float(drift_threshold)

    @property
    def trusted_subgoal_ids(self) -> frozenset[str] | None:
        return self._trusted

    def check(
        self,
        plan: Mapping,
        original_goal: str,
        current_state_seq: int,
        plan_created_seq: int,
    ) -> str | list[str]:
        """Run all three detectors. Returns ``"clean"`` or the issue list.

        Malformed input is never "clean": a plan the defense cannot parse
        is reported as all three issues (it cannot be shown fresh,
        uninjected, or on-scope).
        """
        try:
            stale = self._is_stale(plan, current_state_seq, plan_created_seq)
            injected = self._is_injected(plan)
            drifted = self._is_drifted(original_goal, plan)
        except PlanDefenseError:
            return [ISSUE_STALE_PLAN, ISSUE_PLAN_INJECTION, ISSUE_SCOPE_DRIFT]
        issues: list[str] = []
        if stale:
            issues.append(ISSUE_STALE_PLAN)
        if injected:
            issues.append(ISSUE_PLAN_INJECTION)
        if drifted:
            issues.append(ISSUE_SCOPE_DRIFT)
        return "clean" if not issues else issues

    def check_report(
        self,
        plan: Mapping,
        original_goal: str,
        current_state_seq: int,
        plan_created_seq: int,
    ) -> DefenseReport:
        """Same as :meth:`check` but returns a frozen :class:`DefenseReport`."""
        result = self.check(plan, original_goal, current_state_seq, plan_created_seq)
        if result == "clean":
            return DefenseReport(clean=True, issues=())
        return DefenseReport(clean=False, issues=tuple(result))

    # -- internals ----------------------------------------------------

    def _is_stale(self, plan: Mapping, current_state_seq: int, plan_created_seq: int) -> bool:
        _subgoal_ids(plan)
        current_state_seq = _validate_seq(current_state_seq, "current_state_seq")
        plan_created_seq = _validate_seq(plan_created_seq, "plan_created_seq")
        if plan_created_seq > current_state_seq:
            return True
        return (current_state_seq - plan_created_seq) > self._stale_threshold

    def _is_injected(self, plan: Mapping) -> bool:
        ids = _subgoal_ids(plan)
        if self._trusted is None:
            raise PlanDefenseError("PlanDefense has no trusted_subgoal_ids installed")
        return any(sid not in self._trusted for sid in ids)

    def _is_drifted(self, original_goal: str, plan: Mapping) -> bool:
        if not isinstance(original_goal, str):
            raise PlanDefenseError("original_goal must be a string")
        goal_kw = _keywords(original_goal)
        if not goal_kw:
            return True
        subgoal_kw: set[str] = set()
        for desc in _subgoal_descriptions(plan):
            subgoal_kw |= _keywords(desc)
        if not subgoal_kw:
            return True
        overlap = len(goal_kw & subgoal_kw) / len(goal_kw)
        return overlap < self._drift_threshold


def main() -> None:
    plan = {
        "subgoals": [
            {"id": "a", "description": "fetch user profile data"},
            {"id": "b", "description": "summarize user profile for display"},
        ]
    }
    defense = PlanDefense(trusted_subgoal_ids={"a", "b"})
    result = defense.check(plan, "fetch and summarize user profile", 50, 10)
    assert result == "clean", result
    stale = defense.check(plan, "fetch and summarize user profile", 500, 10)
    assert stale == ["stale-plan"], stale
    print("plan-defense OK: stale/injection/drift detectors wired")


if __name__ == "__main__":
    main()
