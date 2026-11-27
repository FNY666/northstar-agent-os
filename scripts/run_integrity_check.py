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
from scripts.swe_bench_integrity import CheckStore, _test_lists, judge_instance  # noqa: E402


def _conditions(arguments) -> dict:
    """The conditions the probes are graded under.

    The harness version decides how a patch is graded, so a verdict cannot
    be read without it. The platform matters as well: the evaluation images
    are built for one architecture, and on another one they run under
    emulation, which is a different environment in every way that shows.
    """
    import platform

    conditions = {
        "harness": "swebench",
        "timeout": arguments.timeout,
        "probes": ["gold", "empty"],
        "run_id": arguments.run_id,
        "host_platform": platform.machine(),
    }
    try:
        import swebench

        version = getattr(swebench, "__version__", None)
        if version:
            conditions["harness_version"] = version
    except Exception:  # noqa: BLE001
        pass
    return conditions


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

    # The conditions under which the probes are graded. They go into the
    # payload so that the stored verdicts say which harness produced them.
    conditions = _conditions(arguments)
    gold_patches = {}
    if arguments.gold_patches:
        gold_patches = json.loads(Path(arguments.gold_patches).read_text(encoding="utf-8"))

    wanted = set(arguments.task)
    tasks = [t for t in sample["tasks"] if not wanted or t["instance_id"] in wanted]

    workdir = Path(f"/tmp/swe-integrity-{os.getpid()}")
    workdir.mkdir(parents=True, exist_ok=True)
    os.chdir(workdir)

    # The store keeps the verdicts on disk as they arrive, so a run that
    # takes days can be resumed and a machine that dies loses nothing.
    store = CheckStore(arguments.output)
    store.conditions = conditions
    raw: dict[str, dict] = store.raw

    for task in tasks:
        instance_id = task["instance_id"]
        upstream = _upstream_instance(task)
        try:
            _pull_image(client, upstream["image"])
        except Exception as exc:  # noqa: BLE001
            raw[instance_id] = {"error": f"could not obtain the image: {exc}"[:600]}
            item = judge_instance(instance_id, None, None)
            store.add(item, raw.get(instance_id))
            store.flush(arguments.sample)
            print(f"{instance_id}: {item.verdict} -- {item.detail}")
            continue
            continue
        spec = make_test_spec(upstream)

        if store.done(instance_id):
            print(f"{instance_id}: already checked, skipping")
            continue
        outcomes: dict[str, str | None] = {}
        test_lists: dict[str, object] = {}
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
            outcomes[name] = _outcome_of(report, get_resolution_status, instance_id)
            test_lists[name] = _test_lists(report)

        item = judge_instance(
            instance_id,
            outcomes.get("gold"),
            outcomes.get("empty"),
            test_lists.get("gold"),
            test_lists.get("empty"),
        )
        store.add(item, raw.get(instance_id))
        # The verdicts are written after every instance: a full run takes
        # days, and a machine that dies must not throw away the work that
        # already succeeded.
        store.flush(arguments.sample)
        print(f"{instance_id}: {item.verdict} -- {item.detail}")

    report = store.report()
    payload = {
        "sample": arguments.sample,
        "conditions": store.conditions,
        "summary": report.summary(),
        "instances": [
            {
                "instance_id": item.instance_id,
                "verdict": item.verdict,
                "gold_outcome": item.gold_outcome,
                "empty_outcome": item.empty_outcome,
                "detail": item.detail,
                "fail_to_pass_passing_when_empty": item.fail_to_pass_passing_when_empty,
                "gold_failures_also_passing_when_empty": item.gold_failures_also_passing_when_empty,
                "failures_under_both": item.failures_under_both,
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


def _outcome_of(report: dict, get_resolution_status, instance_id: str) -> str | None:
    """The resolution status of one probe, or None when there is no verdict.

    ``resolved`` is False for a probe that ran and did not fix the issue, and
    that False is a verdict. Treating it as "no verdict" turns every failing
    probe into an inconclusive one.
    """
    if not isinstance(report, dict):
        return None
    # The upstream helper reads FAIL_TO_PASS and PASS_TO_PASS at the top level
    # of the report; run_instance nests them under "tests_status".
    graded = dict(report)
    tests_status = graded.pop("tests_status", None)
    if isinstance(tests_status, dict):
        graded.update(tests_status)
    try:
        # The upstream helper reads one report, not a mapping of ids.
        status = get_resolution_status(graded)
    except Exception:  # noqa: BLE001
        status = None
    if status:
        return str(status)
    resolved = report.get("resolved")
    if resolved is not None:
        return "True" if resolved else "False"
    return None


if __name__ == "__main__":
    raise SystemExit(main())
