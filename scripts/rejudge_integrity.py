"""Re-judge an integrity check from the logs it already produced.

A check over fifty tasks takes days. When the rules of the judgement change
-- when a new failure mode is recognised -- the verdicts that the old rules
produced have to be brought up to date. Re-running the evaluations would
cost days again; the logs of the run hold everything the judgement needs,
so the verdicts can be recomputed from them.

Two things are read. The exit status the upstream runner recorded tells
whether the run itself broke, which is not evidence about the task. The
grader reports the check kept tell which tests failed, which is what
separates a task with a broken fail-to-pass list from a task whose
pass-to-pass list cannot pass in this environment.

Nothing is re-evaluated here: no evaluation is repeated and no result the
run produced is changed. Only what those results mean is re-decided.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

# The script is run from the repository root, but it must also work when it
# is run from anywhere else.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.swe_bench_infra import probe_infra_failure  # noqa: E402
from scripts.swe_bench_integrity import (  # noqa: E402
    CheckStore,
    InstanceIntegrity,
    IntegrityReport,
    _test_lists,
    judge_instance,
)


def _probe_reports(store: CheckStore, instance_id: str) -> tuple[Any, Any]:
    """The grader reports of the two probes, if the check kept them."""
    raw = store.raw.get(instance_id) or {}
    return raw.get("gold"), raw.get("empty")


def rejudge(
    store_path: str | Path,
    log_root: str | Path,
    run_id: str,
) -> IntegrityReport:
    """Recompute the verdicts from the logs and reports of a finished run."""
    store = CheckStore(store_path)
    report = IntegrityReport()
    for entry in store.items:
        instance_id = entry.instance_id
        gold_report, empty_report = _probe_reports(store, instance_id)

        infra: dict[str, str] = {}
        for probe in ("gold", "empty"):
            broken = probe_infra_failure(log_root, run_id, f"integrity-{probe}", instance_id)
            if broken:
                infra[probe] = broken

        if infra:
            item = InstanceIntegrity(
                instance_id=instance_id,
                verdict="inconclusive",
                gold_outcome=entry.gold_outcome,
                empty_outcome=entry.empty_outcome,
                detail="the run broke -- "
                + "; ".join(f"{k}: {v}" for k, v in sorted(infra.items())),
                fail_to_pass_passing_when_empty=list(entry.fail_to_pass_passing_when_empty),
                gold_failures_also_passing_when_empty=list(
                    entry.gold_failures_also_passing_when_empty
                ),
                failures_under_both=list(entry.failures_under_both),
            )
        else:
            item = judge_instance(
                instance_id,
                entry.gold_outcome,
                entry.empty_outcome,
                _test_lists(gold_report),
                _test_lists(empty_report),
            )
        report.add(item)
    return report


def payload_of(report: IntegrityReport, sample: str = "") -> dict[str, Any]:
    """The stored form of the recomputed verdicts."""
    return {
        "sample": sample,
        "summary": report.summary(),
        "instances": [item.to_json() for item in report.instances],
    }


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", required=True, help="the integrity check output")
    parser.add_argument("--log-root", required=True, help="the directory the run worked in")
    parser.add_argument("--run-id", required=True, help="the run id the logs carry")
    parser.add_argument("--output", required=True, help="where to write the re-judged check")
    parser.add_argument("--sample", default="")
    arguments = parser.parse_args()

    report = rejudge(arguments.check, arguments.log_root, arguments.run_id)
    Path(arguments.output).write_text(
        json.dumps(payload_of(report, arguments.sample), indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report.summary(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
