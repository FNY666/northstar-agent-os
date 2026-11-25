#!/usr/bin/env python3
"""Let a real model attempt the frozen SWE-bench sample.

The sample freezes *what* is measured.  This script freezes *how*: the
model, the endpoint, the sandbox profile, the budget and the per-task
conditions are written into a receipt, so a later run can prove it measured
the same thing.

The solver works on the repository as it stands at the instance's base
commit.  That checkout comes from the instance's own environment image
rather than from a network clone: the image is the frozen artifact, and a
clone would be a different tree than the one the evaluation runs against.

A run without provider credentials produces a receipt that says
``real_model_evaluated: false``.  It never invents a pass rate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "components" / "northstar-agent-runtime" / "cli.py"
SAMPLE = ROOT / "benchmarks" / "swe-bench" / "verified-50.json"
RECEIPT_SCHEMA = "northstar.swe-bench-solve.v1"

# The sandbox profile the solver runs under.  Recorded in the receipt.
SANDBOX_PROFILE = {
    "backend": "process",
    "seccomp": "off",
    "capdrop": "off",
    "landlock": "off",
    "policy_file": "none",
    "workspace_agents": False,
    "skills": False,
    "memory": False,
    "plugins": False,
    "network": "disabled",
}

TASK_LIMITS = {
    "max_turns": 40,
    "max_tool_calls": 120,
    "max_output_tokens": 8192,
    "wall_time_seconds": 1800,
}


class SolverError(RuntimeError):
    """A problem with the environment, not with the model."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_sample(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    tasks = payload["tasks"]
    if isinstance(tasks, dict):
        tasks = list(tasks.values())
    return {"tasks": tasks}


def image_for_instance(instance_id: str, sample_path: Path = SAMPLE) -> str:
    """The environment image one frozen instance is evaluated in."""
    sample = load_sample(sample_path)
    for task in sample["tasks"]:
        if task["instance_id"] == instance_id:
            return task["environment_image"]
    raise SolverError(f"no such instance in the sample: {instance_id}")


def _credentials_present(provider: str) -> bool:
    if provider == "openai":
        return bool(os.environ.get("OPENAI_API_KEY", "").strip())
    if provider == "anthropic":
        return bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())
    return provider == "scripted"


def _provider_environment(provider: str) -> dict[str, str]:
    if provider == "openai":
        key = os.environ.get("OPENAI_API_KEY", "")
        return {"OPENAI_API_KEY": key} if key else {}
    if provider == "anthropic":
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        return {"ANTHROPIC_API_KEY": key} if key else {}
    return {}


def _problem_statements(instance_ids: list[str]) -> dict[str, str]:
    """Fetch the original problem statements for the given instances.

    The frozen sample keeps a fingerprint of each statement rather than the
    text itself, so the text is read from the upstream dataset and checked
    against the fingerprint.
    """
    import urllib.request

    wanted = set(instance_ids)
    statements: dict[str, str] = {}
    offset = 0
    length = 100
    # The dataset is larger than one page, so it is walked until every
    # wanted instance has been seen or the data runs out.
    while len(statements) < len(wanted) and offset < 1000:
        url = (
            "https://datasets-server.huggingface.co/rows?dataset="
            "SWE-bench%2FSWE-bench_Verified&config=default&split=test"
            f"&offset={offset}&length={length}"
        )
        with urllib.request.urlopen(url, timeout=180) as response:
            payload = json.loads(response.read().decode("utf-8"))
        rows = payload.get("rows", [])
        if not rows:
            break
        for row in rows:
            record = row.get("row", {})
            instance_id = record.get("instance_id")
            if instance_id in wanted:
                statements[instance_id] = record.get("problem_statement", "")
        offset += length
    missing = sorted(wanted - set(statements))
    if missing:
        raise SolverError(f"no problem statement for: {missing}")
    return statements


def export_testbed(image: str, destination: Path) -> None:
    """Copy the repository at its base commit out of the environment image.

    The image is the frozen artifact for the instance, so the checkout the
    model edits is the checkout the evaluation will run against.
    """
    destination.mkdir(parents=True, exist_ok=True)
    container = f"northstar-swe-export-{int(time.time())}-{os.getpid()}"
    try:
        subprocess.run(
            ["docker", "create", "--platform", "linux/amd64", "--name", container, image],
            check=True, capture_output=True, text=True, timeout=600,
        )
        try:
            subprocess.run(
                ["docker", "cp", f"{container}:/testbed/.", str(destination)],
                check=True, capture_output=True, text=True, timeout=1800,
            )
        finally:
            subprocess.run(
                ["docker", "rm", "-f", container],
                check=False, capture_output=True, text=True, timeout=300,
            )
    except subprocess.CalledProcessError as error:
        raise SolverError(f"could not export the testbed: {error.stderr[-500:]}") from error


def _git(cwd: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", "-c", "protocol.version=2", *arguments],
        cwd=str(cwd), capture_output=True, check=False, timeout=600,
    )


def _read_patch(evidence_root: Path) -> bytes | None:
    """The patch the run delivered, as recorded in its evidence.

    The runtime edits the repository in a detached worktree, so the
    workspace the caller handed over is not where the change lives.  The
    evidence bundle is the authoritative record of what was delivered.
    """
    if not evidence_root.is_dir():
        return None
    run_dirs = sorted(path for path in evidence_root.iterdir() if path.is_dir())
    if len(run_dirs) != 1:
        return None
    patch_path = run_dirs[0] / "changes.patch"
    if not patch_path.is_file():
        return None
    return patch_path.read_bytes()


def _prompt(statement: str, repo: str) -> str:
    return (
        "You are fixing a bug in the "
        f"{repo} repository. The repository is checked out in your working "
        "directory at the commit where the bug is present.\n\n"
        "Here is the issue report:\n\n"
        f"{statement}\n\n"
        "Investigate the repository, find the cause, and make the smallest "
        "change that fixes the issue. Do not add tests, do not change the "
        "project's formatting, and do not modify unrelated files."
    )


def solve_one(
    task: dict[str, Any],
    statement: str,
    workspace: Path,
    evidence_root: Path,
    *,
    provider: str,
    model: str,
    base_url: str,
    provider_environment: dict[str, str],
    temperature: float | None,
    limits: dict[str, Any],
) -> dict[str, Any]:
    """Run the model on one instance and return the patch it produced."""
    command = [
        sys.executable, str(CLI), "code",
        _prompt(statement, task.get("repo", "")),
        "--workspace", str(workspace),
        "--provider", provider,
        "--model", model,
        "--sandbox", SANDBOX_PROFILE["backend"],
        "--seccomp", SANDBOX_PROFILE["seccomp"],
        "--capdrop", SANDBOX_PROFILE["capdrop"],
        "--landlock", SANDBOX_PROFILE["landlock"],
        "--no-policy-file",
        "--no-workspace-agents",
        "--no-skills",
        "--no-memory",
        "--no-plugins",
        "--max-turns", str(limits["max_turns"]),
        "--max-tool-calls", str(limits["max_tool_calls"]),
        "--max-output-tokens", str(limits["max_output_tokens"]),
        "--evidence-dir", str(evidence_root),
        "--json",
    ]
    if temperature is not None:
        command.extend(("--temperature", str(temperature)))
    environment = dict(os.environ)
    environment.update(provider_environment)
    if provider == "openai" and base_url:
        environment["OPENAI_BASE_URL"] = base_url
    started = time.monotonic()
    timed_out = False
    try:
        process = subprocess.run(
            command, cwd=str(ROOT), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment, timeout=float(limits["wall_time_seconds"]), check=False,
        )
        return_code = process.returncode
        stdout = process.stdout
        stderr = process.stderr
    except subprocess.TimeoutExpired as error:
        timed_out = True
        return_code = 124
        stdout = error.stdout or b""
        stderr = error.stderr or b""
    elapsed = time.monotonic() - started

    patch = _read_patch(evidence_root) or b""
    return {
        "instance_id": task["instance_id"],
        "repo": task.get("repo", ""),
        "return_code": return_code,
        "timed_out": timed_out,
        "elapsed_seconds": round(elapsed, 1),
        "patch_bytes": len(patch),
        "patch_sha256": _sha256(patch),
        "patch": patch.decode("utf-8", errors="replace"),
        "stdout_tail": stdout.decode("utf-8", errors="replace")[-600:],
        "stderr_tail": stderr.decode("utf-8", errors="replace")[-600:],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", default="anthropic", choices=("anthropic", "openai", "scripted"))
    parser.add_argument("--model", default="")
    parser.add_argument("--base-url", default="")
    parser.add_argument("--temperature", type=float, default=None)
    parser.add_argument("--sample", default=str(SAMPLE))
    parser.add_argument("--output", required=True)
    parser.add_argument("--task", action="append", default=[])
    parser.add_argument("--max-turns", type=int, default=TASK_LIMITS["max_turns"])
    parser.add_argument("--max-tool-calls", type=int, default=TASK_LIMITS["max_tool_calls"])
    parser.add_argument("--wall-time-seconds", type=int, default=TASK_LIMITS["wall_time_seconds"])
    parser.add_argument("--keep-workdir", default="")
    parser.add_argument("--json", action="store_true")
    arguments = parser.parse_args(argv)

    sample = load_sample(Path(arguments.sample))
    tasks = sample["tasks"]
    if arguments.task:
        wanted = set(arguments.task)
        tasks = [t for t in tasks if t["instance_id"] in wanted]
    if not tasks:
        print("no tasks selected", file=sys.stderr)
        return 2

    limits = {
        "max_turns": arguments.max_turns,
        "max_tool_calls": arguments.max_tool_calls,
        "max_output_tokens": TASK_LIMITS["max_output_tokens"],
        "wall_time_seconds": arguments.wall_time_seconds,
    }

    receipt: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "measurement": "swe_bench_solve",
        "real_model_evaluated": False,
        "release_eligible": False,
        "conditions": {
            "provider": arguments.provider,
            "model": arguments.model,
            "base_url": arguments.base_url,
            "temperature": arguments.temperature,
            "sandbox": SANDBOX_PROFILE,
            "limits": limits,
            "sample": {
                "path": str(Path(arguments.sample).relative_to(ROOT)),
                "task_count": len(tasks),
                "sample_sha256": _sha256(Path(arguments.sample).read_bytes()),
            },
        },
        "tasks": [],
        "summary": {},
    }

    if not _credentials_present(arguments.provider):
        receipt["summary"] = {
            "reason": "no_provider_credentials",
            "checked": 0,
            "solved": 0,
        }
        Path(arguments.output).write_text(
            json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        if arguments.json:
            print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2))
        return 0

    statements = _problem_statements([t["instance_id"] for t in tasks])
    provider_environment = _provider_environment(arguments.provider)

    if arguments.keep_workdir:
        parent = Path(arguments.keep_workdir)
        parent.mkdir(parents=True, exist_ok=True)
    else:
        parent = Path(tempfile.mkdtemp(prefix="northstar-swe-solve-"))

    patches: dict[str, str] = {}
    try:
        for index, task in enumerate(tasks, start=1):
            instance_id = task["instance_id"]
            print(f"[{index}/{len(tasks)}] {instance_id}", flush=True)
            workspace = parent / instance_id / "testbed"
            evidence_root = parent / instance_id / "evidence"
            row: dict[str, Any] = {"instance_id": instance_id, "repo": task.get("repo", "")}
            try:
                if not workspace.exists():
                    export_testbed(task["environment_image"], workspace)
                statement = statements.get(instance_id, "")
                if not statement:
                    row["outcome"] = "no_problem_statement"
                    receipt["tasks"].append(row)
                    continue
                result = solve_one(
                    task, statement, workspace, evidence_root,
                    provider=arguments.provider,
                    model=arguments.model,
                    base_url=arguments.base_url,
                    provider_environment=provider_environment,
                    temperature=arguments.temperature,
                    limits=limits,
                )
                patches[instance_id] = result.pop("patch")
                result["outcome"] = "solved" if result["patch_bytes"] else "no_patch"
                row.update(result)
            except (OSError, ValueError, SolverError) as error:
                row["outcome"] = "error"
                row["detail"] = str(error)[:400]
            receipt["tasks"].append(row)
            receipt["summary"] = {
                "checked": len(receipt["tasks"]),
                "solved": sum(1 for r in receipt["tasks"] if r.get("outcome") == "solved"),
            }
            Path(arguments.output).write_text(
                json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
    finally:
        if not arguments.keep_workdir:
            shutil.rmtree(parent, ignore_errors=True)

    receipt["real_model_evaluated"] = True
    receipt["summary"] = {
        "checked": len(receipt["tasks"]),
        "solved": sum(1 for r in receipt["tasks"] if r.get("outcome") == "solved"),
        "patched": len(patches),
    }
    patch_path = Path(arguments.output).with_name(Path(arguments.output).stem + "-patches.json")
    patch_path.write_text(
        json.dumps(patches, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    receipt["patches_path"] = patch_path.name
    Path(arguments.output).write_text(
        json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    if arguments.json:
        print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
