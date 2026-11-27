"""Judge whether a frozen benchmark sample can be trusted.

A benchmark is only a measurement of the model if its grader is itself
correct. Two properties decide that, and both are checkable without a model:

1. The reference patch -- the human-written fix -- must be graded as a pass.
   If it fails, the task's tests disagree with the task, and no patch can
   be fairly judged on it.
2. The empty patch must be graded as a failure. If it passes, the task
   cannot tell a fix from a no-op, and every score on it is noise.

Both checks run through the same grader as the real evaluation, so a
passing check says something about the grader, not about a re-implementation
of it. The verdicts are kept per instance: a task that fails the check is
reported as untrustworthy rather than silently dropped.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

# A task that cannot distinguish a fix from a no-op gives no signal.
TRUSTWORTHY = "trustworthy"
GOLD_REJECTED = "gold_patch_rejected"
EMPTY_ACCEPTED = "empty_patch_accepted"
INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class InstanceIntegrity:
    """What the two probe patches said about one task."""

    instance_id: str
    verdict: str
    gold_outcome: str | None = None
    empty_outcome: str | None = None
    detail: str = ""

    @property
    def is_trustworthy(self) -> bool:
        return self.verdict == TRUSTWORTHY


@dataclass
class IntegrityReport:
    """The verdict for a whole sample."""

    instances: list[InstanceIntegrity] = field(default_factory=list)

    def add(self, item: InstanceIntegrity) -> None:
        self.instances.append(item)

    @property
    def trustworthy(self) -> list[InstanceIntegrity]:
        return [i for i in self.instances if i.is_trustworthy]

    @property
    def untrustworthy(self) -> list[InstanceIntegrity]:
        return [i for i in self.instances if not i.is_trustworthy]

    def summary(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for item in self.instances:
            counts[item.verdict] = counts.get(item.verdict, 0) + 1
        return {
            "instances": len(self.instances),
            "trustworthy": len(self.trustworthy),
            "untrustworthy": len(self.untrustworthy),
            "verdicts": counts,
        }

    def instance_ids(self) -> list[str]:
        return [i.instance_id for i in self.trustworthy]


def judge_instance(
    instance_id: str,
    gold_outcome: str | None,
    empty_outcome: str | None,
) -> InstanceIntegrity:
    """Classify one task from the two probe verdicts.

    ``None`` means the grader produced no verdict -- the machine crashed or
    the run timed out. That is not evidence of a broken task, so the task is
    reported as inconclusive rather than counted against the sample.
    """
    if gold_outcome is None or empty_outcome is None:
        missing = "gold" if gold_outcome is None else "empty"
        return InstanceIntegrity(
            instance_id=instance_id,
            verdict=INCONCLUSIVE,
            gold_outcome=gold_outcome,
            empty_outcome=empty_outcome,
            detail=f"no verdict for the {missing} patch",
        )
    if not _is_pass(gold_outcome):
        return InstanceIntegrity(
            instance_id=instance_id,
            verdict=GOLD_REJECTED,
            gold_outcome=gold_outcome,
            empty_outcome=empty_outcome,
            detail="the reference patch was rejected",
        )
    if _is_pass(empty_outcome):
        return InstanceIntegrity(
            instance_id=instance_id,
            verdict=EMPTY_ACCEPTED,
            gold_outcome=gold_outcome,
            empty_outcome=empty_outcome,
            detail="the empty patch was accepted",
        )
    return InstanceIntegrity(
        instance_id=instance_id,
        verdict=TRUSTWORTHY,
        gold_outcome=gold_outcome,
        empty_outcome=empty_outcome,
    )


def _is_pass(outcome: str) -> bool:
    """A probe passes only when the grader says the task is solved.

    A partial resolution is not a pass: the reference patch is expected to
    fix the task completely, and an empty patch that half-satisfies the
    tests is not evidence that the task is broken, so it is not treated as
    one here.
    """
    return outcome.strip().upper() in {"RESOLVED_FULL", "RESOLVED"}


def report_from_probes(
    probes: Iterable[tuple[str, str | None, str | None]],
) -> IntegrityReport:
    """Build a report from ``(instance_id, gold_outcome, empty_outcome)``."""
    report = IntegrityReport()
    for instance_id, gold, empty in probes:
        report.add(judge_instance(instance_id, gold, empty))
    return report
