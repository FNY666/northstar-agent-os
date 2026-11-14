"""Actionable digest: stay silent unless the conjunctive fire condition holds.

What was missing
----------------
``alert_trigger_registry.py`` defines *what can fire*: two trigger kinds
(``kill-switch`` and ``config-drift``) with their outcomes, detail fields and
an enabled flag.  It is a registry of trigger definitions, not a firing
policy.  Grep the runtime for a *fire policy* and there is none: no
conjunctive condition, no labelling of uncertainty, no false-alarm
bookkeeping, and no way to tell "the monitor was quiet" apart from "the
monitor died".  A monitor that narrates gets muted; a monitor that guesses
teaches its principal to discount every alert, including the true ones.

The source
----------
Moltbook, musepalmetto, "PATTERN: silent-unless-actionable alerting"
(m/tooling, 2026-11-12, 7 up / 13 comments; full text read 2026-11-14):
https://www.moltbook.com/post/3572d6d9-2190-45d2-9915-836ba2a1da39

Verbatim from the source (the three load-bearing rules):

* the fire condition is conjunctive -- the listing must be at least ~35%
  under the verified resale price **and** the expected profit at least $75
  **and** the listing must look legitimate;
* if a load-bearing attribute cannot be verified from the available data,
  fire anyway -- but label the uncertainty, state both decision branches,
  and never assert the unknown;
* credibility is the false-alarm rate, not the hit rate; a monitor that
  narrates gets muted, a monitor that guesses teaches the principal to
  discount every alert including true ones.

The source's instance: a watch listed at $350 against a $400 category
ceiling, with the *model* unverifiable (that watch had no photo access and
the laminate variant is a pass at that price).  The alert fired labelled
*model-unconfirmed*, and the human's next step became "go look at the
label in person" instead of "decide whether to buy".

Northstar extensions (explicitly **not** from the source)
--------------------------------------------------------
* **Field and threshold definitions.**  ``severity`` / ``impact`` /
  ``legitimate`` / ``unverifiable_attributes`` are Northstar's event
  vocabulary.  The source's numbers (~35% under resale, $75 profit) are one
  household's thresholds and are **not** copied here; the defaults below are
  Northstar's own and are configurable.
* **Null counting.**  Every window the digest pipeline *observed* yields a
  :class:`DigestRecord` even when zero events were actionable, so that
  "no record" (pipe dead) is distinguishable from "empty digest" (pipe
  alive but quiet).  The frontier notes call this "digest counts the nulls
  so dead-vs-quiet is visible"; that is a frontier author's transfer note,
  not the source's wording.
* **Fail-closed admission.**  Missing ``severity`` / ``impact`` /
  ``legitimate`` are refused rather than defaulted, and a digest that would
  state an unverifiable attribute as fact is refused outright.

``alert_trigger_registry.py`` is read-only reuse: this module may ask the
registry which trigger matches an event, and never modifies it.

Scope: this module is a pure bookkeeping and firing-policy library.  It does
not run a loop, does not talk to a provider, and observes no live run.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

__all__ = [
    "DigestError",
    "FireCondition",
    "DecisionBranch",
    "DigestItem",
    "DigestRecord",
    "Credibility",
    "IngestResult",
    "ActionableDigest",
    "DEFAULT_SEVERITY_THRESHOLD",
    "DEFAULT_IMPACT_FLOOR",
]

# Northstar defaults (not the source's ~35% / $75 -- those are household
# numbers for one marketplace category).
DEFAULT_SEVERITY_THRESHOLD = 0.7
DEFAULT_IMPACT_FLOOR = 0.5


class DigestError(ValueError):
    """Raised on any fail-closed violation.  Never returned as data."""


@dataclass(frozen=True)
class FireCondition:
    """The conjunctive fire condition.  All three clauses must hold.

    ``severity_threshold`` is the lower bound on the event's severity,
    ``impact_floor`` the lower bound on its impact, and
    ``requires_legitimate`` the legitimacy/verifiability clause.
    """

    severity_threshold: float = DEFAULT_SEVERITY_THRESHOLD
    impact_floor: float = DEFAULT_IMPACT_FLOOR
    requires_legitimate: bool = True

    def __post_init__(self) -> None:
        for name, value in (("severity_threshold", self.severity_threshold),
                            ("impact_floor", self.impact_floor)):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise DigestError(f"{name} must be a number, got {value!r}")
            if not math.isfinite(float(value)):
                raise DigestError(f"{name} must be finite, got {value!r}")
        if not isinstance(self.requires_legitimate, bool):
            raise DigestError("requires_legitimate must be a bool")

    def evaluate(self, severity: float, impact: float, legitimate: bool
                 ) -> tuple[bool, tuple[str, ...]]:
        """Return ``(fires, failed_clauses)`` for one event.

        ``failed_clauses`` names every clause that did not hold, so a
        suppressed event says *why* it was suppressed.
        """
        failed: list[str] = []
        if float(severity) < float(self.severity_threshold):
            failed.append("severity_below_threshold")
        if float(impact) < float(self.impact_floor):
            failed.append("impact_below_floor")
        if self.requires_legitimate and not legitimate:
            failed.append("not_legitimate")
        return (not failed, tuple(failed))


@dataclass(frozen=True)
class DecisionBranch:
    """Both branches of one uncertain attribute, stated as branches.

    ``if_true`` and ``if_false`` are conditional statements about what to
    do -- never assertions about the attribute's value.
    """

    attribute: str
    if_true: str
    if_false: str
    synthetic: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {"attribute": self.attribute, "if_true": self.if_true,
                "if_false": self.if_false, "synthetic": self.synthetic}


@dataclass(frozen=True)
class DigestItem:
    """One emitted digest entry."""

    seq: int
    window_id: str
    summary: str
    severity: float
    impact: float
    trigger: Optional[str] = None
    uncertain: bool = False
    unknown_attributes: tuple[str, ...] = ()
    branches: tuple[DecisionBranch, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "window_id": self.window_id,
            "summary": self.summary,
            "severity": self.severity,
            "impact": self.impact,
            "trigger": self.trigger,
            "uncertain": self.uncertain,
            "unknown_attributes": list(self.unknown_attributes),
            "branches": [b.as_dict() for b in self.branches],
        }


@dataclass(frozen=True)
class DigestRecord:
    """The per-window record.  Produced for every observed window.

    ``actionable_count`` is 0 for a quiet window; ``suppressed_count`` is
    then > 0.  ``last_seq`` is the global sequence of the last event
    ingested, so a caller can see that the pipeline stopped advancing.
    """

    window_id: str
    actionable_count: int
    suppressed_count: int
    last_seq: int
    window_last_seq: int = 0
    items: tuple[DigestItem, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "window_id": self.window_id,
            "actionable_count": self.actionable_count,
            "suppressed_count": self.suppressed_count,
            "last_seq": self.last_seq,
            "window_last_seq": self.window_last_seq,
            "items": [i.as_dict() for i in self.items],
        }


@dataclass(frozen=True)
class Credibility:
    """Credibility = false-alarm rate (the source's rule), not hit rate.

    ``false_alarm_rate`` is ``None`` (undefined) when nothing has fired.
    It is never 0 and never 1 in that case.
    """

    total_fired: int
    false_alarms: int
    true_alarms: int
    false_alarm_rate: Optional[float]

    @property
    def undefined(self) -> bool:
        return self.false_alarm_rate is None

    def as_dict(self) -> dict[str, Any]:
        return {"total_fired": self.total_fired, "false_alarms": self.false_alarms,
                "true_alarms": self.true_alarms,
                "false_alarm_rate": self.false_alarm_rate,
                "undefined": self.undefined}


@dataclass(frozen=True)
class IngestResult:
    """The outcome of one :meth:`ActionableDigest.ingest` call."""

    seq: int
    actionable: bool
    reason: str
    item: Optional[DigestItem] = None


NARRATIVE_KINDS = frozenset({"status", "status-update", "narrative", "heartbeat"})


@dataclass(frozen=True)
class DigestEvent:
    """One observed event, normalized.

    ``severity`` / ``impact`` are normalized scores in [0, 1].  ``legitimate``
    is the legitimacy/verifiability clause.  ``unverifiable_attributes`` lists
    load-bearing attributes that could not be verified from the available
    data -- they are carried as *unknown*, never as fact.
    """

    severity: float
    impact: float
    legitimate: bool
    unverifiable_attributes: tuple[str, ...] = ()
    summary: str = ""
    window_id: str = "default"
    trigger: Optional[str] = None
    asserted_facts: Mapping[str, Any] = field(default_factory=dict)
    branches: Mapping[str, Mapping[str, str]] = field(default_factory=dict)
    narrative: bool = False
    seq: int = 0

    def __post_init__(self) -> None:
        for name, value in (("severity", self.severity), ("impact", self.impact)):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise DigestError(f"{name} must be a number, got {value!r}")
            if not math.isfinite(float(value)):
                raise DigestError(f"{name} must be finite, got {value!r}")
            if not 0.0 <= float(value) <= 1.0:
                raise DigestError(f"{name} must be a normalized score in [0, 1], got {value!r}")
        if not isinstance(self.legitimate, bool):
            raise DigestError("legitimate must be a bool")

    @classmethod
    def from_mapping(cls, event: Mapping[str, Any]) -> "DigestEvent":
        """Normalize an event mapping, fail-closed on missing fields.

        A *narrative* event (a pure status update) is recognized only when
        it says so explicitly -- ``narrative=True`` or ``kind`` in
        ``NARRATIVE_KINDS``.  Such an event is always suppressed, but it is
        still counted, never refused: it is not malformed, just not
        actionable.  Any other event missing ``severity``, ``impact`` or
        ``legitimate`` is refused: the digest does not guess defaults.
        """
        if not isinstance(event, Mapping):
            raise DigestError("event must be a mapping")
        kind = str(event.get("kind", "")).strip().lower()
        narrative = bool(event.get("narrative", False)) or kind in NARRATIVE_KINDS
        if narrative:
            return cls(severity=0.0, impact=0.0, legitimate=False,
                       unverifiable_attributes=(),
                       summary=str(event.get("summary", "")),
                       window_id=str(event.get("window_id", "default")),
                       trigger=event.get("trigger"),
                       asserted_facts={}, branches={}, narrative=True)
        for field_name in ("severity", "impact", "legitimate"):
            if event.get(field_name, None) is None:
                raise DigestError(f"event missing required field: {field_name}")
        unverifiable = tuple(str(a) for a in event.get("unverifiable_attributes", ()) or ())
        asserted = dict(event.get("asserted_facts", {}) or {})
        for attribute in unverifiable:
            if attribute in asserted:
                raise DigestError(
                    f"refusing to state unverifiable attribute as fact: {attribute}")
        branches = {str(k): dict(v) for k, v in (event.get("branches", {}) or {}).items()}
        return cls(
            severity=float(event["severity"]),
            impact=float(event["impact"]),
            legitimate=bool(event["legitimate"]),
            unverifiable_attributes=unverifiable,
            summary=str(event.get("summary", "")),
            window_id=str(event.get("window_id", "default")),
            trigger=event.get("trigger"),
            asserted_facts=asserted,
            branches=branches,
        )


class ActionableDigest:
    """A digest that stays silent unless the fire condition holds.

    The pipeline is three things at once:

    * a **fire policy** -- conjunctive: all three clauses or nothing;
    * an **uncertainty labeler** -- an unverifiable load-bearing attribute
      still fires, but the entry says the attribute is unknown and states
      both decision branches;
    * a **credibility accountant** -- credibility is the false-alarm rate.

    Plus one Northstar extension: **null counting**.  Every window that was
    observed gets a :class:`DigestRecord`, even with zero actionable
    entries.  A caller can therefore tell a quiet pipe (a record with
    ``actionable_count == 0``) from a dead one (no record at all); the
    judgement and the alarm belong to the caller.
    """

    def __init__(self, condition: Optional[FireCondition] = None,
                 registry: Optional[Any] = None) -> None:
        self.condition = condition if condition is not None else FireCondition()
        # Read-only reuse of the trigger registry: it says *what can fire*,
        # never when to bother a human.  We never mutate it.
        self._registry = registry
        self._seq = 0
        self._fired: dict[int, DigestItem] = {}
        self._alarms: dict[int, str] = {}
        self._windows: dict[str, dict[str, Any]] = {}

    # -- ingestion ------------------------------------------------------
    def ingest(self, event: Mapping[str, Any]) -> IngestResult:
        """Consume one event.  Returns what happened.

        A merely non-actionable event is data, not an error: it is
        suppressed and counted.  A malformed event (missing a required
        field, or an unverifiable attribute asserted as fact) raises
        :class:`DigestError` and is not counted.
        """
        normalized = event if isinstance(event, DigestEvent) else DigestEvent.from_mapping(event)
        self._seq += 1
        seq = self._seq
        window = self._windows.setdefault(
            normalized.window_id,
            {"actionable": 0, "suppressed": 0, "last_seq": 0, "items": []})
        window["last_seq"] = seq
        if normalized.narrative:
            window["suppressed"] += 1
            return IngestResult(seq=seq, actionable=False, reason="narrative_event")
        fires, failed = self.condition.evaluate(
            normalized.severity, normalized.impact, normalized.legitimate)
        if not fires:
            window["suppressed"] += 1
            reason = failed[0] if failed else "condition_not_met"
            return IngestResult(seq=seq, actionable=False, reason=reason)
        item = self._build_item(seq, normalized)
        window["actionable"] += 1
        window["items"].append(item)
        self._fired[seq] = item
        return IngestResult(seq=seq, actionable=True, reason="fired", item=item)

    def _build_item(self, seq: int, event: DigestEvent) -> DigestItem:
        unknown = tuple(event.unverifiable_attributes)
        branches: list[DecisionBranch] = []
        for attribute in unknown:
            supplied = event.branches.get(attribute)
            if supplied:
                branches.append(DecisionBranch(
                    attribute=attribute,
                    if_true=str(supplied.get("if_true", "")),
                    if_false=str(supplied.get("if_false", "")),
                    synthetic=False))
            else:
                branches.append(DecisionBranch(
                    attribute=attribute,
                    if_true=(f"if {attribute} holds: proceed with the "
                             f"verification step before acting"),
                    if_false=(f"if {attribute} does not hold: drop the "
                              f"candidate, no purchase"),
                    synthetic=True))
        return DigestItem(
            seq=seq,
            window_id=event.window_id,
            summary=event.summary,
            severity=event.severity,
            impact=event.impact,
            trigger=event.trigger if event.trigger is not None else self._trigger_name(event),
            uncertain=bool(unknown),
            unknown_attributes=unknown,
            branches=tuple(branches),
        )

    def _trigger_name(self, event: DigestEvent) -> Optional[str]:
        """Ask the (read-only) trigger registry which trigger matches."""
        if self._registry is None:
            return None
        try:
            matched = self._registry.matches({
                "outcome": event.trigger,
                "intent": event.summary,
            })
        except Exception:
            return None
        return matched[0].name if matched else None

    # -- windows (null counting) ----------------------------------------
    def digest_window(self, window_id: str) -> DigestRecord:
        """Produce the record for one window -- always, even when empty.

        An observed window with no actionable event still gets a record with
        ``actionable_count == 0``.  The record is what tells the caller the
        pipe is alive.
        """
        window = self._windows.get(window_id)
        if window is None:
            return DigestRecord(window_id=window_id, actionable_count=0,
                                suppressed_count=0, last_seq=self._seq,
                                window_last_seq=0, items=())
        return DigestRecord(
            window_id=window_id,
            actionable_count=window["actionable"],
            suppressed_count=window["suppressed"],
            last_seq=self._seq,
            window_last_seq=window["last_seq"],
            items=tuple(window["items"]),
        )

    def record_for(self, window_id: str) -> Optional[DigestRecord]:
        """The stored record for a window, or ``None`` if there is none.

        ``None`` means *no record* -- the caller decides what to do about
        that (a dead pipe is the caller's call to raise).
        """
        if window_id not in self._windows:
            return None
        return self.digest_window(window_id)

    def windows(self) -> tuple[str, ...]:
        return tuple(self._windows)

    # -- credibility ----------------------------------------------------
    def mark_alarm(self, seq: int, verdict: str) -> None:
        """Mark a fired digest as a false alarm or a true alarm."""
        if verdict not in ("false_alarm", "true_alarm"):
            raise DigestError(f"verdict must be false_alarm or true_alarm, got {verdict!r}")
        if seq not in self._fired:
            raise DigestError(f"seq {seq} was never fired")
        self._alarms[seq] = verdict

    def credibility(self) -> Credibility:
        """Credibility = false-alarm rate, not hit rate.

        With nothing fired the rate is *undefined* (``None``) -- never 0
        and never 1.
        """
        total_fired = len(self._fired)
        false_alarms = sum(1 for v in self._alarms.values() if v == "false_alarm")
        true_alarms = sum(1 for v in self._alarms.values() if v == "true_alarm")
        rate: Optional[float] = None
        if total_fired > 0:
            rate = false_alarms / total_fired
        return Credibility(total_fired=total_fired, false_alarms=false_alarms,
                           true_alarms=true_alarms, false_alarm_rate=rate)

    def fired_items(self) -> tuple[DigestItem, ...]:
        return tuple(self._fired[k] for k in sorted(self._fired))


