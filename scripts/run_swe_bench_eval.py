#!/usr/bin/env python3
"""Evaluate patches against the frozen SWE-bench Verified sample.

The upstream ``swebench.harness`` is used as-is for the evaluation and
for the verdict, so a result here means what it means upstream.  This
script only adds what the harness does not provide: a frozen task list,
a receipt that records the conditions, and a verdict per task that can
be compared with another run.

The environment images are ``linux/amd64``.  On an arm64 host they run
under QEMU user-mode emulation, which is slow but faithful.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE = REPO_ROOT / "benchmarks" / "swe-bench" / "verified-50.json"
DIGESTS = REPO_ROOT / "benchmarks" / "swe-bench" / "verified-50.digests.json"

# The upstream verdicts, verbatim. A task counts as solved only when the
# upstream harness says it is fully resolved.
RESOLVED_FULL = "RESOLVED_FULL"
RESOLVED_PARTIAL = "RESOLVED_PARTIAL"
RESOLVED_NO = "RESOLVED_NO"
FAIL_TO_PASS = "FAIL_TO_PASS"
PASS_TO_PASS = "PASS_TO_PASS"
ERROR = "ERROR"


def load_sample(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _upstream_available() -> bool:
    try:
        import swebench  # noqa: F401
    except Exception:
        return False
    return True


def _docker_platform() -> str:
    try:
        out = subprocess.run(
            ["docker", "info", "--format", "{{.Architecture}}"],
            capture_output=True, text=True, timeout=60,
        ).stdout.strip()
    except Exception:
        return ""
    return {"x86_64": "linux/amd64", "aarch64": "linux/arm64"}.get(out, out)


def _image_platform(image: str) -> str:
    """The platform the published image is actually built for.

    The environment images are published for one architecture only.  A host
    of a different architecture has to pull that one and let the kernel's
    emulation run it, and asking the registry for the host's own
    architecture fails with a confusing 404.
    """
    try:
        out = subprocess.run(
            ["docker", "manifest", "inspect", image],
            capture_output=True, text=True, timeout=300, check=False,
        )
        manifest = json.loads(out.stdout)
    except (OSError, ValueError, subprocess.SubprocessError):
        return ""
    for entry in manifest.get("manifests", []):
        platform = entry.get("platform") or {}
        architecture = platform.get("architecture")
        operating_system = platform.get("os")
        if architecture and operating_system and architecture != "unknown":
            return f"{operating_system}/{architecture}"
    return ""


def _pull_image(client: Any, image: str) -> None:
    """Make sure the instance's image is present, for the right platform.

    The upstream runner pulls an image that is missing locally, and it
    pulls it for the host's own platform.  On a host that is not the
    architecture the images are published for, that pull fails even
    though the image exists.  Pulling it here, for the platform the
    evaluation actually runs on, keeps the upstream runner on its normal
    path: it finds the image locally and uses it.
    """
    images = getattr(client, "images", None)
    if images is None:
        return
    try:
        images.get(image)
        return
    except Exception:  # noqa: BLE001 - not present yet, keep going
        pass
    platform = _image_platform(image) or _docker_platform()
    if not platform:
        return
    try:
        images.pull(image, platform=platform)
    except Exception:  # noqa: BLE001 - the upstream runner pulls it too
        pass


APPLY_PATCH_PASS = ">>>>> Applied Patch"
APPLY_PATCH_FAIL = ">>>>> Patch Apply Failed"

# Signs that the run broke the machine rather than the code under test.
# A segmentation fault in the test process is not something the model can
# be blamed for, and the receipt has to say so.
INFRA_MARKERS = (
    "Segmentation fault",
    "Bus error",
    "Killed",
    "out of memory",
    "Cannot allocate memory",
)


def _infra_failure(log_root: Path, run_id: str, instance_id: str) -> str:
    """A sign that the run itself broke, or an empty string."""
    base = log_root / "logs" / "run_evaluation" / run_id / "northstar" / instance_id
    for name in ("run_instance.log", "test_output.txt"):
        try:
            text = base.joinpath(name).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for marker in INFRA_MARKERS:
            if marker in text:
                return marker
    return ""


def _apply_marker(log_root: Path, run_id: str, instance_id: str) -> str:
    """What the upstream runner recorded about applying the patch.

    The upstream report field ``patch_successfully_applied`` is not about the
    patch at all: the grader sets it only after it has parsed the test
    output, so a patch that applied cleanly but made the tests error out
    comes back with the field false.  The runner writes the truth into the
    log instead, and that is what this reads.

    Returns "pass", "fail" or "unknown".
    """
    base = log_root / "logs" / "run_evaluation" / run_id / "northstar" / instance_id
    # The runner writes the marker into its instance log, and the test
    # output is a separate file; read both so the marker is found wherever
    # the runner put it.
    text = ""
    for name in ("run_instance.log", "test_output.txt"):
        try:
            text += base.joinpath(name).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    if not text:
        return "unknown"
    if APPLY_PATCH_FAIL in text:
        return "fail"
    if APPLY_PATCH_PASS in text:
        return "pass"
    return "unknown"


def evaluate(
    sample: dict[str, Any],
    patches: dict[str, str],
    *,
    run_id: str,
    timeout: int,
    only: list[str] | None = None,
) -> dict[str, Any]:
    """Evaluate every task that has a patch and return a receipt."""
    from swebench.harness.grading import get_resolution_status
    from swebench.harness.constants import FAIL_TO_PASS, PASS_TO_PASS
    from swebench.harness.run_evaluation import run_instance
    from swebench.harness.utils import make_test_spec

    import docker

    client = docker.from_env()
    tasks = sample["tasks"]
    if only:
        wanted = set(only)
        tasks = [t for t in tasks if t["instance_id"] in wanted]

    rows: list[dict[str, Any]] = []
    dataset = {t["instance_id"]: _upstream_instance(t) for t in tasks}
    for task in tasks:
        instance_id = task["instance_id"]
        patch = patches.get(instance_id, "")
        row: dict[str, Any] = {
            "instance_id": instance_id,
            "repo": task["repo"],
            "patch_bytes": len(patch.encode("utf-8")),
            "patch_sha256": _sha256(patch),
            "outcome": ERROR,
            "resolved": False,
        }
        if not patch:
            row["outcome"] = "no_patch_delivered"
            rows.append(row)
            continue
        try:
            _pull_image(client, dataset[instance_id]["image"])
        except Exception as exc:  # noqa: BLE001 - report it, do not stop the run
            row["outcome"] = ERROR
            row["detail"] = f"could not obtain the environment image: {exc}"[:600]
            rows.append(row)
            continue
        spec = make_test_spec(dataset[instance_id])
        pred = {
            "model_name_or_path": "northstar",
            "model_patch": patch,
            "instance_id": instance_id,
        }
        try:
            # The upstream runner owns the container, the patch application
            # and the evaluation script; its verdict is the upstream verdict.
            result = run_instance(
                spec, pred, client, run_id, timeout=timeout,
            )
            if result is None:
                # The upstream runner returns nothing when the run times
                # out.  That is a timeout, not a verdict about the patch,
                # and the receipt has to say which it is.
                row["outcome"] = "evaluation_timeout"
                row["resolved"] = False
                rows.append(row)
                continue
            _, report = result
            # The upstream runner returns a report keyed by instance id;
            # the grading detail sits under "tests_status".
            entry = report.get(instance_id, report)
            detail = entry.get("tests_status")
            marker = _apply_marker(Path.cwd(), run_id, instance_id)
            row["patch_apply_marker"] = marker
            row["patch_successfully_applied"] = bool(entry.get("patch_successfully_applied"))
            row["infra_failure"] = bool(entry.get("infra_failure"))
            if marker == "fail":
                row["outcome"] = "patch_not_applied"
                row["resolved"] = False
                rows.append(row)
                continue
            if marker == "unknown" and not row["patch_successfully_applied"]:
                # The log did not say, and the grader did not get as far as
                # reading test results.  The patch application is unknown,
                # which is not a verdict about the model either way.
                row["outcome"] = "patch_not_applied"
                row["resolved"] = False
                rows.append(row)
                continue
            if marker == "pass" and not row["patch_successfully_applied"]:
                # The patch applied, but the grader could not read the test
                # results, so it has no verdict.  That is not the same as the
                # patch failing to apply, and it is not a pass either.
                infra = _infra_failure(Path.cwd(), run_id, instance_id)
                row["infra_failure_reason"] = infra
                row["outcome"] = (
                    "evaluation_infrastructure_failure" if infra
                    else "evaluation_inconclusive"
                )
                row["resolved"] = False
                rows.append(row)
                continue
            if not isinstance(detail, dict) or FAIL_TO_PASS not in detail:
                # The patch applied but the upstream produced no per-test
                # detail.  The upstream grader still knows how to judge the
                # report it built, so let it speak.
                detail = entry
            status = get_resolution_status(detail)
            row["outcome"] = status
            row["resolved"] = status == RESOLVED_FULL
            row["fail_to_pass"] = list(detail.get(FAIL_TO_PASS, {}).get("success", []))
            row["pass_to_pass"] = list(detail.get(PASS_TO_PASS, {}).get("success", []))
        except Exception as exc:  # noqa: BLE001 - a broken instance must not stop the run
            import traceback
            row["outcome"] = ERROR
            row["detail"] = traceback.format_exc()[-1200:]
        rows.append(row)
    passed = sum(1 for r in rows if r["resolved"])
    return {
        "schema": "northstar.swe-bench-eval.v1",
        "run_id": run_id,
        "summary": {
            "checked": len(rows),
            "passed": passed,
            "failed": len(rows) - passed,
            "failure_kinds": _kinds(rows),
        },
        "tasks": rows,
    }


def _upstream_instance(task: dict[str, Any]) -> dict[str, Any]:
    """Shape a frozen task the way the upstream harness expects it."""
    return {
        "instance_id": task["instance_id"],
        "repo": task["repo"],
        "base_commit": task["base_commit"],
        "version": task["version"],
        "FAIL_TO_PASS": task["fail_to_pass"],
        "PASS_TO_PASS": task["pass_to_pass"],
        "image": task.get("image") or task["environment_image"],
        "eval_type": task.get("eval_type"),
        "log_parser": task.get("log_parser"),
        "eval_script": _as_object(task.get("eval_script")),
    }


def _as_object(value: Any) -> Any:
    """The upstream dataset carries the eval script as a JSON string."""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _logger():
    from swebench.logger import setup_logger
    return setup_logger("swe-eval", Path("/tmp/swe-eval.log"))


def _sha256(text: str) -> str:
    import hashlib
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _kinds(rows: list[dict[str, Any]]) -> dict[str, int]:
    kinds: dict[str, int] = {}
    for row in rows:
        if row["resolved"]:
            continue
        kinds[row["outcome"]] = kinds.get(row["outcome"], 0) + 1
    return kinds


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--patches", required=True, help="JSON file: instance_id -> patch text")
    parser.add_argument("--sample", default=str(SAMPLE))
    parser.add_argument("--output", required=True)
    parser.add_argument("--run-id", default="northstar")
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--task", action="append", help="limit to one instance; repeatable")
    parser.add_argument("--workdir", help="where the upstream harness writes its logs")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if not _upstream_available():
        print(
            "the upstream swebench harness is required; install it with "
            "`pip install swebench==5.0.2`",
            file=sys.stderr,
        )
        return 2
    # The upstream harness writes its logs to a path relative to the
    # working directory; keep them out of the repository.
    workdir = Path(args.workdir or f"/tmp/swe-eval-{os.getpid()}")
    workdir.mkdir(parents=True, exist_ok=True)
    os.chdir(workdir)

    sample = load_sample(Path(args.sample))
    patches = json.loads(Path(args.patches).read_text(encoding="utf-8"))
    receipt = evaluate(
        sample, patches,
        run_id=args.run_id, timeout=args.timeout, only=args.task,
    )
    receipt["conditions"] = {
        "sample": Path(args.sample).name,
        "sample_tasks": len(sample["tasks"]),
        "docker_platform": _docker_platform(),
        "harness": "upstream swebench 5.0.2",
    }
    Path(args.output).write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(receipt["summary"], indent=2))
    else:
        print(json.dumps(receipt["summary"], indent=2))
        print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
