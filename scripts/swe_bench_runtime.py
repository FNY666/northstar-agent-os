"""Add what a check cost to its record.

A check over a sample is a run like any other: it takes machine time, and
the time it takes is a property of the tasks, not of the code under test.
Knowing it is what makes a future run comparable -- a check that suddenly
takes twice as long has changed in some way that matters.

The durations come from the upstream runner's own record of each probe's
runtime, so they describe what actually happened.
"""

from __future__ import annotations

import collections
import re
from pathlib import Path
from typing import Any

_RUNTIME = re.compile(r"Test runtime: ([0-9_.]+)")


def probe_runtimes(log_root: str | Path, run_id: str) -> dict[str, dict[str, float]]:
    """The seconds each probe of each task took, read from the run's logs."""
    base = Path(log_root) / "logs" / "run_evaluation" / run_id
    out: dict[str, dict[str, float]] = collections.defaultdict(dict)
    if not base.exists():
        return {}
    for log in base.glob("*/*/run_instance.log"):
        probe = log.parent.parent.name
        instance_id = log.parent.name
        try:
            text = log.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        found = _RUNTIME.findall(text)
        if not found:
            continue
        out[instance_id][probe] = float(found[-1].replace("_", ""))
    return dict(out)


def runtime_summary(runtimes: dict[str, dict[str, float]]) -> dict[str, Any]:
    """What the run cost, in machine time."""
    total = sum(sum(v.values()) for v in runtimes.values())
    probes = sum(len(v) for v in runtimes.values())
    per_probe: dict[str, list[float]] = collections.defaultdict(list)
    for values in runtimes.values():
        for probe, seconds in values.items():
            per_probe[probe].append(seconds)
    slowest = sorted(
        ((sum(v.values()), k) for k, v in runtimes.items() if v),
        reverse=True,
    )[:5]
    return {
        "probes_completed": probes,
        "test_seconds_total": round(total, 1),
        "test_hours_total": round(total / 3600.0, 2),
        "mean_seconds_per_probe": (
            round(total / probes, 1) if probes else None
        ),
        "by_probe": {
            probe: round(sum(values) / len(values), 1)
            for probe, values in sorted(per_probe.items())
        },
        "slowest_tasks": [
            {"instance_id": name, "seconds": round(seconds, 1)}
            for seconds, name in slowest
        ],
    }


def main() -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--log-root",
        action="append",
        required=True,
        help="a directory the run worked in; may be given more than once, "
             "because a run that was restarted keeps its earlier logs elsewhere",
    )
    parser.add_argument("--run-id", required=True, help="the run id the logs carry")
    parser.add_argument("--output", required=True, help="where to write the summary")
    arguments = parser.parse_args()

    # A run that was restarted leaves its earlier probes in an earlier
    # directory. The later run picks up where the earlier one stopped, so
    # the two are counted together.
    runtimes: dict[str, dict[str, float]] = {}
    for root in arguments.log_root:
        for instance_id, values in probe_runtimes(root, arguments.run_id).items():
            runtimes.setdefault(instance_id, {}).update(values)

    summary = runtime_summary(runtimes)
    Path(arguments.output).write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
