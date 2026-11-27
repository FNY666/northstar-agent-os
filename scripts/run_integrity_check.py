#!/usr/bin/env python3
"""Check that a frozen SWE-bench sample can carry a measurement.

For every instance in the sample this runs two probe patches through the
upstream harness: the human-written reference patch, which must be graded
as solved, and the empty patch, which must be graded as unsolved. A task
that passes both probes separates a fix from a no-op, so the score it
contributes means something; a task that fails either probe does not.

The verdicts are written per instance and summarised. An instance whose
probe produced no verdict at all -- a crashed machine, a timeout -- is
reported as inconclusive rather than counted against the sample.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.run_swe_bench_eval import (  # noqa: E402
    _pull_image,
    _upstream_instance,
    load_sample,
)
from scripts.swe_bench_integrity import report_from_probes  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--task", action="append", default=[])
    parser.add_argument("--run-id", default="northstar-integrity")
    parser.add_argument("--timeout", type=int, default=5400)
    parser.add_argument("--gold-patches", default="",
                        help="a JSON file mapping instance_id to the reference patch")
    arguments = parser.parse_args(argv)

    import docker
    from swebench.harness.utils import make_test_spec
    from swebench.harness.run_evaluation import run_instance
    from swebench.harness.grading import get_resolution_status

    client = docker.from_env()
    sample = load_sample(Path(arguments.sample))
    gold_patches = {}
    if arguments.gold_patches:
        gold_patches = json.loads(Path(arguments.gold_patches).read_text(encoding="utf-8"))

    wanted = set(arguments.task)
    tasks = [t for t in sample["tasks"] if not wanted or t["instance_id"] in wanted]

    workdir = Path(f"/tmp/swe-integrity-{os.getpid()}")
    workdir.mkdir(parents=True, exist_ok=True)
    os.chdir(workdir)

    probes: list[tuple[str, str | None, str | None]] = []
    raw: dict[str, dict] = {}

    for task in tasks:
        instance_id = task["instance_id"]
        upstream = _upstream_instance(task)
        try:
            _pull_image(client, upstream["image"])
        except Exception as exc:  # noqa: BLE001
            raw[instance_id] = {"error": f"could not obtain the image: {exc}"[:600]}
            probes.append((instance_id, None, None))
            continue
        spec = make_test_spec(upstream)

        outcomes: dict[str, str | None] = {}
        for name, patch in (("gold", gold_patches.get(instance_id, "")), ("empty", "")):
            pred = {
                "model_name_or_path": f"integrity-{name}",
                "model_patch": patch,
                "instance_id": instance_id,
            }
            try:
                result = run_instance(
                    spec, pred, client, arguments.run_id, timeout=arguments.timeout,
                    skip_patch=(name == "empty"),
                )
            except Exception as exc:  # noqa: BLE001
                raw.setdefault(instance_id, {})[name] = {"error": str(exc)[:600]}
                outcomes[name] = None
                continue
            if result is None:
                raw.setdefault(instance_id, {})[name] = {"error": "timeout"}
                outcomes[name] = None
                continue
            _, entry = result
            report = entry.get(instance_id, entry)
            raw.setdefault(instance_id, {})[name] = report
            outcomes[name] = _outcome_of(report, get_resolution_status)

        probes.append((instance_id, outcomes.get("gold"), outcomes.get("empty")))

    report = report_from_probes(probes)
    payload = {
        "sample": arguments.sample,
        "summary": report.summary(),
        "instances": [
            {
                "instance_id": item.instance_id,
                "verdict": item.verdict,
                "gold_outcome": item.gold_outcome,
                "empty_outcome": item.empty_outcome,
                "detail": item.detail,
            }
            for item in report.instances
        ],
        "raw": raw,
    }
    Path(arguments.output).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload["summary"], indent=2))
    for item in report.instances:
        if not item.is_trustworthy:
            print(f"{item.instance_id}: {item.verdict} -- {item.detail}")
    return 0


def _outcome_of(report: dict, get_resolution_status) -> str | None:
    """The resolution status of one probe, or None when there is no verdict."""
    if not isinstance(report, dict):
        return None
    status = report.get("resolved")
    if status:
        return str(status)
    try:
        # The upstream helper takes a mapping of instance id to the report.
        return get_resolution_status({"instance": report})
    except Exception:  # noqa: BLE001
        return None


if __name__ == "__main__":
    raise SystemExit(main())
