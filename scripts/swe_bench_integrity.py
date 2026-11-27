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

The upstream grader reports one status per instance (RESOLVED_FULL /
RESOLVED_PARTIAL / RESOLVED_NO). That status hides which tests failed, and
two different failure modes look identical in it: a task whose fail-to-pass
list is too wide, and a task whose pass-to-pass list contains a test that
cannot pass in this environment. The verdicts below are computed from the
test lists themselves, so the two are told apart.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

# A task that cannot distinguish a fix from a no-op gives no signal.
TRUSTWORTHY = "trustworthy"
GOLD_REJECTED = "gold_patch_rejected"
EMPTY_ACCEPTED = "empty_patch_accepted"
GOLD_PARTIAL = "gold_patch_partial"
INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class InstanceIntegrity:
    """What the two probe patches said about one task."""

    instance_id: str
    verdict: str
    gold_outcome: str | None = None
    empty_outcome: str | None = None
    detail: str = ""
    #: Fail-to-pass tests that already pass without any patch. The task
    #: cannot tell a fix from a no-op on them.
    fail_to_pass_passing_when_empty: list[str] = field(default_factory=list)
    #: Tests that failed under the reference patch but passed under the empty
    #: patch. These are the tests that made the reference patch look wrong.
    gold_failures_also_passing_when_empty: list[str] = field(default_factory=list)
    #: Tests that failed under both probes. They cannot distinguish the two.
    failures_under_both: list[str] = field(default_factory=list)

    @property
    def is_trustworthy(self) -> bool:
        return self.verdict == TRUSTWORTHY

    def to_json(self) -> dict[str, Any]:
        return {
            "instance_id": self.instance_id,
            "verdict": self.verdict,
            "gold_outcome": self.gold_outcome,
            "empty_outcome": self.empty_outcome,
            "detail": self.detail,
            "fail_to_pass_passing_when_empty": self.fail_to_pass_passing_when_empty,
            "gold_failures_also_passing_when_empty": self.gold_failures_also_passing_when_empty,
            "failures_under_both": self.failures_under_both,
        }


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


class CheckStore:
    """The verdicts of a check, kept on disk as they arrive.

    A check over a whole sample takes days: every instance is two full
    evaluations. The verdicts are therefore written after each instance, so
    a machine that dies in the middle does not throw away the work that
    already succeeded, and the run can be resumed.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.raw: dict[str, Any] = {}
        self.items: list[InstanceIntegrity] = []
        #: The conditions the probes were graded under. A verdict without
        #: them cannot be compared with another verdict.
        self.conditions: dict[str, Any] = {}
        if self.path.exists():
            self._load()

    def _load(self) -> None:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        self.raw = payload.get("raw", {}) or {}
        self.conditions = payload.get("conditions", {}) or {}
        for entry in payload.get("instances", []) or []:
            self.items.append(
                InstanceIntegrity(
                    instance_id=entry.get("instance_id", ""),
                    verdict=entry.get("verdict", INCONCLUSIVE),
                    gold_outcome=entry.get("gold_outcome"),
                    empty_outcome=entry.get("empty_outcome"),
                    detail=entry.get("detail", ""),
                    fail_to_pass_passing_when_empty=list(entry.get("fail_to_pass_passing_when_empty", [])),
                    gold_failures_also_passing_when_empty=list(
                        entry.get("gold_failures_also_passing_when_empty", [])
                    ),
                    failures_under_both=list(entry.get("failures_under_both", [])),
                )
            )

    def done(self, instance_id: str) -> bool:
        return any(item.instance_id == instance_id for item in self.items)

    def add(
        self,
        item: InstanceIntegrity,
        raw: dict[str, Any] | None = None,
    ) -> None:
        self.items.append(item)
        if raw is not None:
            self.raw[item.instance_id] = raw

    def report(self) -> IntegrityReport:
        report = IntegrityReport()
        for item in self.items:
            report.add(item)
        return report

    def payload(self, sample: str = "") -> dict[str, Any]:
        report = self.report()
        return {
            "sample": sample,
            "conditions": self.conditions,
            "summary": report.summary(),
            "instances": [item.to_json() for item in self.items],
            "raw": self.raw,
        }

    def flush(self, sample: str = "") -> None:
        """Write the verdicts out. Called after every instance."""
        path = self.path
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(self.payload(sample), indent=2) + "\n", encoding="utf-8")
        tmp.replace(path)


def _test_lists(report: Any) -> dict[str, dict[str, list[str]]] | None:
    """The failed and passed test names in one grader report.

    ``run_instance`` returns the grader's report with the test lists under
    ``tests_status``; the lists themselves live under FAIL_TO_PASS and
    PASS_TO_PASS. The failed and the passed names are kept apart, because
    which set a test is in is what tells the failure modes apart.
    """
    if not isinstance(report, dict):
        return None
    status = report.get("tests_status")
    if not isinstance(status, dict):
        return None
    out: dict[str, dict[str, list[str]]] = {}
    for key in ("FAIL_TO_PASS", "PASS_TO_PASS"):
        entry = status.get(key)
        if not isinstance(entry, dict):
            return None
        failed = entry.get("failure") or []
        passed = entry.get("success") or []
        if not isinstance(failed, list) or not isinstance(passed, list):
            return None
        out[key] = {"failed": [str(x) for x in failed], "passed": [str(x) for x in passed]}
    return out


def judge_instance(
    instance_id: str,
    gold_outcome: str | None,
    empty_outcome: str | None,
    gold_tests: dict[str, dict[str, list[str]]] | None = None,
    empty_tests: dict[str, dict[str, list[str]]] | None = None,
) -> InstanceIntegrity:
    """Classify one task from the two probe verdicts.

    ``None`` means the grader produced no verdict -- the machine crashed or
    the run timed out. That is not evidence of a broken task, so the task is
    reported as inconclusive rather than counted against the sample.

    When the test lists are available the verdict is computed from them
    rather than from the upstream status, because the status cannot tell a
    task with a broken fail-to-pass list from a task whose pass-to-pass list
    contains a test that cannot pass here.
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

    if gold_tests is not None and empty_tests is not None:
        return _judge_by_tests(instance_id, gold_outcome, empty_outcome, gold_tests, empty_tests)

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
        detail="the reference patch passes and the empty patch does not",
    )


def _judge_by_tests(
    instance_id: str,
    gold_outcome: str,
    empty_outcome: str,
    gold_tests: dict[str, dict[str, list[str]]],
    empty_tests: dict[str, dict[str, list[str]]],
) -> InstanceIntegrity:
    """Judge from the test lists, which say more than the upstream status."""
    gold_names = _all(gold_tests)
    empty_names = _all(empty_tests)

    # The fail-to-pass set must actually fail without a patch. If it passes
    # with no patch, the task cannot tell a fix from a no-op.
    f2p = set(gold_tests["FAIL_TO_PASS"]["failed"]) | set(gold_tests["FAIL_TO_PASS"]["passed"])
    f2p_passed_when_empty = sorted(f2p & empty_names - set(empty_tests["FAIL_TO_PASS"]["failed"]))

    # Tests that failed under the reference patch but passed with no patch at
    # all cannot have been broken by the patch.
    gold_failed = set(gold_tests["FAIL_TO_PASS"]["failed"]) | set(gold_tests["PASS_TO_PASS"]["failed"])
    empty_failed = set(empty_tests["FAIL_TO_PASS"]["failed"]) | set(empty_tests["PASS_TO_PASS"]["failed"])
    also_passing = sorted(gold_failed & empty_names - empty_failed)
    failed_under_both = sorted(gold_failed & empty_failed)

    if _is_pass(gold_outcome) and not _is_pass(empty_outcome):
        return InstanceIntegrity(
            instance_id=instance_id,
            verdict=TRUSTWORTHY,
            gold_outcome=gold_outcome,
            empty_outcome=empty_outcome,
            detail="the reference patch passes and the empty patch does not",
            gold_failures_also_passing_when_empty=also_passing,
            failures_under_both=failed_under_both,
        )

    if f2p_passed_when_empty:
        return InstanceIntegrity(
            instance_id=instance_id,
            verdict=EMPTY_ACCEPTED,
            gold_outcome=gold_outcome,
            empty_outcome=empty_outcome,
            detail=(
                "the fail-to-pass tests already pass without a patch: "
                f"{len(f2p_passed_when_empty)} of them"
            ),
            fail_to_pass_passing_when_empty=f2p_passed_when_empty,
            gold_failures_also_passing_when_empty=also_passing,
            failures_under_both=failed_under_both,
        )

    if also_passing:
        # The reference patch fails only on tests that pass without any
        # patch. The task's own fail-to-pass list disagrees with the
        # reference solution.
        return InstanceIntegrity(
            instance_id=instance_id,
            verdict=GOLD_PARTIAL,
            gold_outcome=gold_outcome,
            empty_outcome=empty_outcome,
            detail=(
                "the reference patch fails on tests that pass without a patch: "
                f"{len(also_passing)} of them"
            ),
            gold_failures_also_passing_when_empty=also_passing,
            failures_under_both=failed_under_both,
        )

    if not _is_pass(gold_outcome):
        return InstanceIntegrity(
            instance_id=instance_id,
            verdict=GOLD_REJECTED,
            gold_outcome=gold_outcome,
            empty_outcome=empty_outcome,
            detail="the reference patch was rejected",
            failures_under_both=failed_under_both,
        )

    return InstanceIntegrity(
        instance_id=instance_id,
        verdict=EMPTY_ACCEPTED,
        gold_outcome=gold_outcome,
        empty_outcome=empty_outcome,
        detail="the empty patch was accepted",
        failures_under_both=failed_under_both,
    )


def _all(tests: dict[str, dict[str, list[str]]]) -> set[str]:
    names: set[str] = set()
    for entry in tests.values():
        names.update(entry["failed"])
        names.update(entry["passed"])
    return names


def _is_pass(outcome: str) -> bool:
    """A probe passes only when the grader says the task is solved.

    A partial resolution is not a pass: the reference patch is expected to
    fix the task completely, and an empty patch that half-satisfies the
    tests is not evidence that the task is broken, so it is not treated as
    one here.
    """
    return outcome.strip().upper() in {"RESOLVED_FULL", "RESOLVED"}


def report_from_probes(
    probes: Iterable[tuple],
) -> IntegrityReport:
    """Build a report from the probe verdicts.

    Each probe is ``(instance_id, gold_outcome, empty_outcome)``, optionally
    followed by the two test lists. The lists are used when they are there,
    because they say which tests failed, not just whether the task passed.
    """
    report = IntegrityReport()
    for probe in probes:
        instance_id, gold, empty = probe[0], probe[1], probe[2]
        gold_tests = probe[3] if len(probe) > 3 else None
        empty_tests = probe[4] if len(probe) > 4 else None
        report.add(judge_instance(instance_id, gold, empty, gold_tests, empty_tests))
    return report
