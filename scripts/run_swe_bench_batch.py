#!/usr/bin/env python3
"""Run the frozen SWE-bench sample end to end, and resume where it stopped.

The solver and the evaluator are separate programs on purpose: the solver
runs the model, the evaluator runs the upstream harness inside the
instance's environment image.  This script is the piece that drives them
one instance at a time, keeps the receipts, and can be started again after
an interruption without redoing the work that already finished.

Every instance leaves two receipts behind:

    <out>/solve-<instance>.json   what the model attempted
    <out>/eval-<instance>.json    what the upstream harness decided

An instance whose evaluation receipt already exists is skipped, so the
script is safe to re-run.  The patch file is never truncated; it only
grows.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOLVE = ROOT / "scripts" / "solve_swe_bench.py"
EVAL = ROOT / "scripts" / "run_swe_bench_eval.py"


def _load(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _write(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _merge_patches(path: Path, extra: dict[str, str]) -> int:
    """Add the patches to the shared file without ever losing the old ones."""
    current: dict[str, str] = {}
    if path.exists():
        try:
            current = _load(path)
        except (OSError, ValueError):
            current = {}
    current.update(extra)
    _write(path, current)
    return len(current)


def _run(command: list[str], log: Path) -> int:
    with log.open("w", encoding="utf-8") as handle:
        return subprocess.run(command, stdout=handle, stderr=subprocess.STDOUT, check=False).returncode


def _image_for(instance_id: str) -> str:
    """The environment image one frozen instance is evaluated in."""
    from importlib.util import module_from_spec, spec_from_file_location
    spec = spec_from_file_location("swe_solver", SOLVE)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.image_for_instance(instance_id)


def _ensure_image(image: str, log_path: Path) -> bool:
    """Make sure the environment image is present, for its own platform.

    The images are published for one architecture only, and the solver
    exports the repository out of them, so the pull has to name that
    architecture rather than the host's.
    """
    inspect = subprocess.run(
        ["docker", "image", "inspect", image],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
    )
    if inspect.returncode == 0:
        return True
    with log_path.open("w", encoding="utf-8") as handle:
        code = subprocess.run(
            ["docker", "pull", "--platform", "linux/amd64", image],
            stdout=handle, stderr=subprocess.STDOUT, check=False,
        ).returncode
    return code == 0


def _docker_rmi(image: str) -> None:
    subprocess.run(["docker", "rmi", image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    subprocess.run(["docker", "image", "prune", "-f"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def _instance_ids(sample: dict[str, Any]) -> list[str]:
    return [task["instance_id"] for task in sample["tasks"]]


def run_batch(
    *,
    sample: dict[str, Any],
    out: Path,
    provider: str,
    model: str,
    base_url: str,
    temperature: float | None,
    timeout: int,
    python: str,
    eval_python: str,
    max_turns: int | None = None,
    keep_images: bool = False,
    log: Any = print,
) -> dict[str, Any]:
    """Solve and evaluate every instance that has no evaluation receipt yet."""
    out.mkdir(parents=True, exist_ok=True)
    patch_file = out / "patches.json"
    if not patch_file.exists():
        _write(patch_file, {})

    done: list[str] = []
    skipped: list[str] = []
    failed: list[dict[str, str]] = []

    # Receipts that were already there when this run started, and that say
    # the model was never evaluated.  They come from a run without
    # credentials, and they are worth another try now.
    stale_receipts: set[str] = set()
    for task in sample["tasks"]:
        instance_id = task["instance_id"]
        receipt = out / f"solve-{instance_id}.json"
        if not receipt.exists():
            continue
        try:
            data = _load(receipt)
        except (OSError, ValueError):
            continue
        if data.get("real_model_evaluated") is False:
            stale_receipts.add(instance_id)

    for instance_id in _instance_ids(sample):
        eval_receipt = out / f"eval-{instance_id}.json"
        if eval_receipt.exists():
            skipped.append(instance_id)
            log(f"SKIP_DONE {instance_id}")
            continue

        image = ""
        try:
            image = _image_for(instance_id)
        except Exception as exc:  # noqa: BLE001 - report it, do not crash the batch
            log(f"IMAGE_UNKNOWN {instance_id}: {exc}")
        if image and not _ensure_image(image, out / f"pull-{instance_id}.log"):
            log(f"PULL_FAILED {instance_id}")
            failed.append({"instance_id": instance_id, "stage": "pull", "code": "pull_failed"})
            continue

        solve_receipt = out / f"solve-{instance_id}.json"
        # A receipt left by an earlier run that never had credentials is not
        # a result: it says the model was not evaluated.  This run does have
        # credentials, so that instance is solved again.  A receipt from this
        # run is left alone: it is the answer to the question just asked.
        if solve_receipt.exists() and instance_id in stale_receipts:
            log(f"STALE_NO_CREDENTIALS {instance_id}, solving again")
            solve_receipt.unlink(missing_ok=True)
            (out / f"solve-{instance_id}-patches.json").unlink(missing_ok=True)
        if not solve_receipt.exists():
            command = [
                python, str(SOLVE),
                "--provider", provider,
                "--model", model,
                "--temperature", str(temperature) if temperature is not None else "",
                "--task", instance_id,
                "--output", str(solve_receipt),
            ]
            if base_url:
                command += ["--base-url", base_url]
            if max_turns is not None:
                command += ["--max-turns", str(max_turns)]
            code = _run([c for c in command if c != ""], out / f"solve-{instance_id}.log")
            if code != 0:
                failed.append({"instance_id": instance_id, "stage": "solve", "code": str(code)})
                log(f"SOLVE_FAILED {instance_id}")
                continue

        produced = out / f"solve-{instance_id}-patches.json"
        if produced.exists():
            count = _merge_patches(patch_file, _load(produced))
            log(f"patches: {count}")
        elif solve_receipt.exists():
            # The solver ran but produced no patch.  That is not the same as
            # an instance the model failed to solve: the run may have had no
            # credentials at all, and the receipt says so.  Evaluating it
            # would put "no patch delivered" into the results, which reads
            # as a verdict on the model.
            try:
                receipt = _load(solve_receipt)
            except (OSError, ValueError):
                receipt = {}
            if not receipt.get("real_model_evaluated", False):
                log(f"NO_CREDENTIALS {instance_id}")
                failed.append({"instance_id": instance_id, "stage": "solve", "code": "no_credentials"})
                continue

        code = _run(
            [
                eval_python, str(EVAL),
                "--patches", str(patch_file),
                "--output", str(eval_receipt),
                "--run-id", f"sb-{instance_id}",
                "--task", instance_id,
                "--timeout", str(timeout),
            ],
            out / f"eval-{instance_id}.log",
        )
        outcome = "unknown"
        if eval_receipt.exists():
            try:
                rows = _load(eval_receipt).get("tasks", [])
                if rows:
                    outcome = str(rows[0].get("outcome"))
            except (OSError, ValueError):
                outcome = "unreadable"
        log(f"EVAL {instance_id} {outcome}")
        if outcome in {"unknown", "unreadable"} or code != 0 and outcome == "unknown":
            failed.append({"instance_id": instance_id, "stage": "eval", "code": str(code)})
        else:
            done.append(instance_id)

        if not keep_images and image:
            _docker_rmi(image)

    return {"solved": done, "skipped": skipped, "failed": failed}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", default=str(ROOT / "benchmarks" / "swe-bench" / "verified-50.json"))
    parser.add_argument("--output", required=True)
    parser.add_argument("--provider", default="openai")
    parser.add_argument("--model", default="")
    parser.add_argument("--base-url", default="")
    parser.add_argument("--temperature", type=float, default=None)
    parser.add_argument("--timeout", type=int, default=5400)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--eval-python", default=sys.executable)
    parser.add_argument("--max-turns", type=int, default=None)
    parser.add_argument("--keep-images", action="store_true")
    parser.add_argument(
        "--api-key-env", default="",
        help="environment variable holding the provider key; the batch refuses to "
             "run without it rather than producing instances with no patch",
    )
    args = parser.parse_args(argv)

    if args.api_key_env and not os.environ.get(args.api_key_env, "").strip():
        print(json.dumps({
            "error": "missing_credentials",
            "variable": args.api_key_env,
            "detail": "the batch needs the provider key in the environment; "
                      "without it every instance would come back with no patch",
        }, indent=1))
        return 2

    sample = _load(Path(args.sample))
    result = run_batch(
        sample=sample,
        out=Path(args.output),
        provider=args.provider,
        model=args.model,
        base_url=args.base_url,
        temperature=args.temperature,
        timeout=args.timeout,
        python=args.python,
        eval_python=args.eval_python,
        max_turns=args.max_turns,
        keep_images=args.keep_images,
    )
    print(json.dumps({k: (len(v) if isinstance(v, list) else v) for k, v in result.items()}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
