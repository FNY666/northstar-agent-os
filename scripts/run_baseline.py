#!/usr/bin/env python3
"""Evaluate instances with no patch applied, to find the tests that fail anyway.

The upstream harness has a negative-test mode for exactly this: run the
instance on the untouched checkout and record which pass-to-pass tests
fail.  Those tests cannot be evidence about a patch.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.run_swe_bench_eval import (  # noqa: E402
    _pull_image,
    _upstream_instance,
    load_sample,
)

SAMPLE = Path(__file__).resolve().parent.parent / "benchmarks" / "swe-bench" / "verified-50.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", default=str(SAMPLE))
    parser.add_argument("--output", required=True)
    parser.add_argument("--task", action="append", required=True)
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--run-id", default="baseline")
    args = parser.parse_args(argv)

    from swebench.harness.run_evaluation import run_instance
    from swebench.harness.utils import make_test_spec
    import docker

    client = docker.from_env()
    sample = load_sample(Path(args.sample))
    wanted = set(args.task)
    tasks = [t for t in sample["tasks"] if t["instance_id"] in wanted]
    missing = wanted - {t["instance_id"] for t in tasks}
    if missing:
        print(f"not in the sample: {sorted(missing)}", file=sys.stderr)
        return 2

    workdir = Path(f"/tmp/swe-baseline-{os.getpid()}")
    workdir.mkdir(parents=True, exist_ok=True)
    os.chdir(workdir)

    report: dict[str, dict] = {}
    for task in tasks:
        instance_id = task["instance_id"]
        upstream = _upstream_instance(task)
        try:
            _pull_image(client, upstream["image"])
        except Exception as exc:  # noqa: BLE001
            report[instance_id] = {"error": f"could not obtain the image: {exc}"[:600]}
            continue
        spec = make_test_spec(upstream)
        pred = {
            "model_name_or_path": "baseline",
            "model_patch": "",
            "instance_id": instance_id,
        }
        try:
            result = run_instance(
                spec, pred, client, args.run_id, timeout=args.timeout, skip_patch=True,
            )
        except Exception as exc:  # noqa: BLE001
            report[instance_id] = {"error": str(exc)[:600]}
            continue
        if result is None:
            report[instance_id] = {"error": "timeout"}
            continue
        _, entry = result
        report[instance_id] = entry.get(instance_id, entry)

    Path(args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.output}")
    for instance_id, entry in report.items():
        detail = entry.get("tests_status", {}) if isinstance(entry, dict) else {}
        p2p = detail.get("PASS_TO_PASS", {}) if isinstance(detail, dict) else {}
        failed = p2p.get("failure", []) if isinstance(p2p, dict) else []
        print(f"{instance_id}: {len(failed)} pass-to-pass failures at baseline")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
