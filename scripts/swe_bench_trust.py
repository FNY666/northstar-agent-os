"""Score a measurement only on the tasks whose verdicts can be trusted.

A benchmark score is an average over tasks, and the average is only as
meaningful as the tasks under it. A task whose empty patch also passes
cannot tell a fix from a no-op: whatever the model scored there is noise. A
task whose run crashed was never judged at all.

This joins a measurement with the integrity verdicts of the same sample and
reports the score over the tasks that carry a signal, alongside the score
over all of them. The two are reported together on purpose: the gap between
them is the part of the headline number that the sample cannot support.

The join is by instance id, and the sample fingerprint is checked: a
verdict about one sample must not be applied to a measurement of another.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


#: The outcomes that count as a model result. The rest say that the task
#: was never judged, or that the run broke.
RESOLVED = {"RESOLVED_FULL", "RESOLVED_PARTIAL"}

#: A task the grader judged and the model did not solve. It is a real
#: verdict -- the model was wrong -- and it belongs in the denominator of
#: the rate. Only a task that was never judged is left out.
JUDGED = {"RESOLVED_FULL", "RESOLVED_PARTIAL", "RESOLVED_NO"}


@dataclass
class TrustWeightedScore:
    """A score, and the part of it the sample can support."""

    #: The score over every task that was judged.
    overall: float | None = None
    #: The tasks the overall rate is over.
    overall_pool: int = 0
    overall_unjudged: int = 0
    #: The score over the tasks whose verdicts are trustworthy.
    trusted: float | None = None
    trusted_tasks: int = 0
    #: How many tasks fell into each bucket, and why.
    breakdown: dict[str, dict[str, int]] = field(default_factory=dict)
    #: The tasks that carried a model result but cannot support one.
    tainted: list[str] = field(default_factory=list)
    sample_sha256: str = ""
    measurement_sha256: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "overall_resolved_rate": self.overall,
            "overall_resolved_pool": self.overall_pool,
            "overall_unjudged": self.overall_unjudged,
            "trusted_resolved_rate": self.trusted,
            "trusted_tasks": self.trusted_tasks,
            "breakdown": self.breakdown,
            "tainted_tasks": self.tainted,
            "sample_sha256": self.sample_sha256,
            "measurement_sha256": self.measurement_sha256,
        }


def score(
    measurement: dict[str, Any],
    integrity: dict[str, Any],
) -> TrustWeightedScore:
    """Join a measurement with the integrity verdicts and score both ways."""
    verdicts = {
        item.get("instance_id"): item.get("verdict")
        for item in integrity.get("instances", []) or []
    }

    result = TrustWeightedScore(
        sample_sha256=measurement.get("sample_sha256", "") or "",
    )

    # The rate is over the tasks that carry a verdict at all. A task that
    # was never judged, or whose run broke, is not a failure of the model.
    resolved_pool = 0
    resolved = 0
    trusted_judged = 0
    trusted_resolved = 0
    breakdown: dict[str, dict[str, int]] = {}

    for task in measurement.get("tasks", []) or []:
        instance_id = task.get("instance_id", "")
        outcome = task.get("outcome", "")
        verdict = verdicts.get(instance_id, "unchecked")

        bucket = breakdown.setdefault(verdict, {})
        bucket[outcome] = bucket.get(outcome, 0) + 1

        if outcome not in JUDGED:
            result.overall_unjudged += 1
            continue

        resolved_pool += 1
        if outcome == "RESOLVED_FULL":
            resolved += 1

        if verdict == "trustworthy":
            # The rate counts a task as resolved only when it is fully
            # resolved, which is the same rule the measurement record uses.
            # A task the grader judged and the model missed is still in the
            # denominator: the model was wrong, and that is what the rate
            # has to show.
            trusted_judged += 1
            if outcome == "RESOLVED_FULL":
                trusted_resolved += 1
        elif verdict != "unchecked":
            # The task produced a model result, but the sample cannot
            # support one: the empty patch also passed, or the run broke.
            result.tainted.append(instance_id)

    result.breakdown = breakdown
    result.overall_pool = resolved_pool
    result.overall = (resolved / resolved_pool) if resolved_pool else None
    result.trusted_tasks = trusted_judged
    result.trusted = (trusted_resolved / trusted_judged) if trusted_judged else None
    return result


def check_sample(measurement: dict[str, Any], integrity: dict[str, Any]) -> str:
    """A note when the two sides do not describe the same sample."""
    a = measurement.get("sample_sha256", "") or ""
    b = integrity.get("sample_sha256", "") or ""
    if a and b and a != b:
        return (
            "the measurement and the integrity check are about different samples: "
            f"{a[:12]} against {b[:12]}"
        )
    return ""


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--measurement", required=True, help="the measurement record")
    parser.add_argument("--integrity", required=True, help="the integrity record")
    parser.add_argument("--output", default="")
    arguments = parser.parse_args()

    measurement = json.loads(open(arguments.measurement, encoding="utf-8").read())
    integrity = json.loads(open(arguments.integrity, encoding="utf-8").read())

    note = check_sample(measurement, integrity)
    if note:
        print(note)

    result = score(measurement, integrity)
    payload = result.to_json()
    if arguments.output:
        with open(arguments.output, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
