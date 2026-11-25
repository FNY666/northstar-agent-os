#!/usr/bin/env python3
"""Measure a real-model baseline on the frozen offline code task pack.

The pack freezes *what* is measured.  This script freezes *how*: the model,
the model version, the sandbox profile, the network policy, the budget, and
the task list are all written into the receipt, so a later run can prove it
measured the same thing.

A run without provider credentials produces a receipt that says
``real_model_evaluated: false``.  It never invents a pass rate.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]
PACK_SCRIPT = ROOT / "scripts" / "run-code-task-pack.py"
SPEC = importlib.util.spec_from_file_location("run_code_task_pack", PACK_SCRIPT)
if SPEC is None or SPEC.loader is None:  # pragma: no cover
    raise RuntimeError(f"cannot load {PACK_SCRIPT}")
PACK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACK)

CLI = ROOT / "components" / "northstar-agent-runtime" / "cli.py"
MANIFEST = PACK.MANIFEST
RECEIPT_SCHEMA = "northstar.code-task-baseline.v1"

# The sandbox profile the baseline is measured under.  It is recorded in the
# receipt and must not change between comparable runs.
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

# Per-task ceilings.  Recorded so a budget change is visible in the receipt.
TASK_LIMITS = {
    "max_turns": 25,
    "max_tool_calls": 60,
    "max_output_tokens": 4096,
    "wall_time_seconds": 300,
}

# The release gate from the blueprint: at least 20 of the 24 frozen tasks.
RELEASE_GATE_TASKS = 20


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


_REDACTED_PATH_PREFIX = "/_redacted-path-sha256/"


def _receipt_base_url(base_url: str) -> str:
    """Keep comparable endpoint identity without persisting URL credentials.

    The original value still goes to the provider. Receipt metadata removes
    userinfo, query strings, fragments and raw path text; a stable path digest
    distinguishes endpoints that share a host without persisting the raw path.
    """
    if not base_url:
        return "(provider default)"
    try:
        parts = urlsplit(base_url)
    except ValueError:
        return "(custom endpoint; URL details redacted)"
    netloc = parts.netloc.rsplit("@", 1)[-1]
    path = (
        f"{_REDACTED_PATH_PREFIX}{_sha256(parts.path.encode('utf-8'))}"
        if parts.path else ""
    )
    return urlunsplit((parts.scheme, netloc, path, "", ""))


def _toolchain() -> dict[str, str]:
    def version(command: list[str]) -> str:
        try:
            done = subprocess.run(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, timeout=30, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return "unavailable"
        return done.stdout.decode("utf-8", errors="replace").strip() or "unavailable"

    return {
        "python": version([sys.executable, "--version"]),
        "node": version(["node", "--version"]),
        "git": version(["git", "--version"]),
        "platform": f"{os.uname().sysname}-{os.uname().machine}",
    }


def _credentials_present(provider: str) -> bool:
    """Report whether this provider has a usable credential *without* reading it."""
    if provider == "scripted":
        # A scripted provider talks to nothing; it needs no credential at all.
        return True
    if provider == "anthropic":
        return bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())
    if provider == "openai":
        return bool(os.environ.get("OPENAI_API_KEY", "").strip())
    return False


def _pack_identity() -> dict[str, Any]:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    return {
        "pack_id": payload.get("pack_id"),
        # Use the pack's own fingerprint so this receipt and the frozen
        # controls summary agree on what the pack is.
        "manifest_sha256": PACK.VALIDATOR.fingerprint(payload),
        "task_ids": [task["id"] for task in payload.get("tasks", [])],
    }


def _prepare_task(task_id: str, destination: Path) -> dict[str, Any]:
    return PACK.prepare(task_id, destination, git_repository=True)


def _provider_environment(provider: str) -> dict[str, str]:
    """The credential the model call needs, and nothing else."""
    if provider == "scripted":
        return {}
    if provider == "anthropic":
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        return {"ANTHROPIC_API_KEY": key} if key else {}
    key = os.environ.get("OPENAI_API_KEY", "")
    return {"OPENAI_API_KEY": key} if key else {}


def _run_model(
    task_id: str,
    fixture: Path,
    checks: list[list[str]],
    evidence_root: Path,
    *,
    provider: str,
    model: str,
    base_url: str,
    provider_environment: dict[str, str],
    temperature: float | None = None,
    script: str = "",
    limits: dict[str, Any],
) -> dict[str, Any]:
    """Run one task with the model and return the delivered patch."""
    command = [
        sys.executable, str(CLI), "code",
        _task_prompt(task_id),
        "--workspace", str(fixture),
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
    if script:
        command.extend(("--script", script))
    for check in checks:
        command.extend(("--check", " ".join(check)))

    started = time.monotonic()
    timed_out = False
    child_environment = {**PACK._environment(fixture), **provider_environment}
    if provider == "openai" and base_url:
        # Endpoint URLs can themselves contain userinfo or query credentials.
        # The CLI supports OPENAI_BASE_URL, so do not expose them in argv/ps.
        child_environment["OPENAI_BASE_URL"] = base_url
    try:
        process = subprocess.run(
            command,
            cwd=str(ROOT),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            # The runtime needs the provider credential; the evaluated code
            # does not, because host checks run in their own clean environment.
            env=child_environment,
            timeout=float(limits["wall_time_seconds"]),
            check=False,
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

    run_dirs = (
        sorted(path for path in evidence_root.iterdir() if path.is_dir())
        if evidence_root.is_dir() else []
    )
    # There must be exactly one run directory: two would mean the measurement
    # cannot attribute a patch to a task.
    evidence_dir = run_dirs[0] if len(run_dirs) == 1 else None
    manifest = _read_json(evidence_dir / "manifest.json") if evidence_dir else {}
    patch_path = evidence_dir / "changes.patch" if evidence_dir else None
    patch = patch_path.read_bytes() if patch_path and patch_path.is_file() else b""
    if not patch:
        # An empty patch is a legitimate outcome (no edit was delivered), but
        # it must not be confused with a patch we simply failed to find.
        patch = b""
    verification = _read_json(evidence_dir / "verification.json") if evidence_dir else {}
    return {
        "return_code": return_code,
        "timed_out": timed_out,
        "elapsed_seconds": round(elapsed, 3),
        "patch_bytes": len(patch),
        "patch_sha256": _sha256(patch) if patch else "",
        "outcome": manifest.get("status", ""),
        "verification": verification,
        "stdout_bytes": len(stdout),
        "stderr_bytes": len(stderr),
        "evidence_present": evidence_dir is not None,
    }


def _task_prompt(task_id: str) -> str:
    payload, task, _ = PACK._load_task(task_id)
    del payload
    return str(task["prompt"])


def _classify(result: dict[str, Any], evaluation: dict[str, Any] | None) -> str:
    if result["timed_out"]:
        return "timeout"
    if evaluation is None:
        return "no_patch_delivered"
    if evaluation.get("ok"):
        return "passed"
    public = evaluation.get("public", [])
    if any(row.get("timed_out") for row in public):
        return "check_timeout"
    if any(row.get("exit_code") != 0 for row in public):
        return "public_check_failed"
    hidden = evaluation.get("hidden", {})
    if hidden.get("exit_code") != 0:
        return "hidden_check_failed"
    return "failed"


def run_baseline(
    *,
    provider: str,
    model: str,
    base_url: str,
    output: Path,
    temperature: float | None = None,
    only: list[str],
    limits: dict[str, Any] | None = None,
    keep_workdir: Path | None = None,
    script: str = "",
) -> dict[str, Any]:
    limits = dict(limits or TASK_LIMITS)
    identity = _pack_identity()
    task_ids = only or identity["task_ids"]
    unknown = [task_id for task_id in task_ids if task_id not in identity["task_ids"]]
    if unknown:
        raise ValueError(f"unknown task ids: {unknown}")

    has_credentials = _credentials_present(provider)
    provider_environment = _provider_environment(provider)
    receipt: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "measurement": "real_model_baseline",
        "real_model_evaluated": False,
        "release_eligible": False,
        "conditions": {
            "provider": provider,
            "model": model,
            "base_url": _receipt_base_url(base_url),
            "temperature": temperature,
            "script": Path(script).name if script else "",
            "sandbox": SANDBOX_PROFILE,
            "limits": limits,
            "toolchain": _toolchain(),
            "pack": {
                "pack_id": identity["pack_id"],
                "manifest_sha256": identity["manifest_sha256"],
            },
        },
        "credentials_present": has_credentials,
        "tasks": [],
        "summary": {},
    }

    if not has_credentials:
        receipt["summary"] = {
            "reason": "no_provider_credentials",
            "checked": 0,
            "passed": 0,
        }
        receipt["release_gate"] = {
            "required_tasks": RELEASE_GATE_TASKS,
            "measured": False,
            "eligible": False,
        }
        _write(output, receipt)
        return receipt

    passed = 0
    failures: dict[str, int] = {}
    costs: list[float] = []
    if keep_workdir is not None:
        keep_workdir.mkdir(parents=True, exist_ok=True)
        temporary = str(keep_workdir)
    else:
        temporary = tempfile.mkdtemp(prefix="northstar-baseline-")
    parent = Path(temporary)
    try:
        for task_id in task_ids:
            fixture = parent / task_id / "fixture"
            evidence_root = parent / task_id / "evidence"
            fixture.mkdir(parents=True, exist_ok=True)
            try:
                _prepare_task(task_id, fixture)
            except (OSError, ValueError) as error:
                failures["prepare_failed"] = failures.get("prepare_failed", 0) + 1
                receipt["tasks"].append({
                    "task_id": task_id, "outcome": "prepare_failed",
                    "detail": str(error)[:400],
                })
                continue
            checks = _task_checks(task_id)
            result = _run_model(
                task_id, fixture, checks, evidence_root,
                provider=provider, model=model, base_url=base_url, limits=limits,
                provider_environment=provider_environment,
                temperature=temperature,
                script=script,
            )
            evaluation = None
            patch = _read_patch(evidence_root)
            if patch is not None:
                try:
                    evaluation = PACK.evaluate_patch(task_id, patch)
                except (OSError, ValueError) as error:
                    result["evaluation_error"] = str(error)[:400]
            classification = _classify(result, evaluation)
            if classification == "passed":
                passed += 1
            else:
                failures[classification] = failures.get(classification, 0) + 1
            cost = _cost_of(result)
            if cost is not None:
                costs.append(cost)
            receipt["tasks"].append({
                "task_id": task_id,
                "outcome": classification,
                "return_code": result["return_code"],
                "timed_out": result["timed_out"],
                "elapsed_seconds": result["elapsed_seconds"],
                "patch_bytes": result["patch_bytes"],
                "patch_sha256": result["patch_sha256"],
                "cost_usd": cost,
                "evaluation_ok": bool(evaluation and evaluation.get("ok")),
            })
    finally:
        if keep_workdir is None:
            shutil.rmtree(temporary, ignore_errors=True)

    checked = len(receipt["tasks"])
    receipt["real_model_evaluated"] = True
    receipt["summary"] = {
        "checked": checked,
        "passed": passed,
        "failed": checked - passed,
        "failure_kinds": dict(sorted(failures.items())),
        "median_cost_usd": round(statistics.median(costs), 6) if costs else None,
        "median_elapsed_seconds": round(
            statistics.median([t["elapsed_seconds"] for t in receipt["tasks"] if "elapsed_seconds" in t]), 3
        ) if receipt["tasks"] else None,
    }
    receipt["release_gate"] = {
        "required_tasks": RELEASE_GATE_TASKS,
        "measured": True,
        "passed": passed,
        "eligible": passed >= RELEASE_GATE_TASKS,
    }
    receipt["release_eligible"] = bool(receipt["release_gate"]["eligible"])
    _write(output, receipt)
    return receipt


def _task_checks(task_id: str) -> list[list[str]]:
    _, task, _ = PACK._load_task(task_id)
    return [list(command) for command in task["public_checks"]]


def _read_patch(evidence_root: Path) -> bytes | None:
    if not evidence_root.is_dir():
        return None
    run_dirs = sorted(path for path in evidence_root.iterdir() if path.is_dir())
    if len(run_dirs) != 1:
        return None
    patch_path = run_dirs[0] / "changes.patch"
    if not patch_path.is_file():
        return None
    return patch_path.read_bytes()


def _cost_of(result: dict[str, Any]) -> float | None:
    verification = result.get("verification") or {}
    usage = verification.get("usage") if isinstance(verification, dict) else None
    if isinstance(usage, dict):
        total = usage.get("cost_usd")
        if isinstance(total, (int, float)):
            return float(total)
    return None


def _write(path: Path, receipt: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", default="anthropic", choices=("anthropic", "openai", "scripted"))
    parser.add_argument(
        "--script",
        default="",
        help="JSON file of scripted turns; only valid with --provider scripted",
    )
    parser.add_argument("--model", default="")
    parser.add_argument("--base-url", default="")
    parser.add_argument(
        "--temperature",
        type=float,
        default=None,
        help="sampling temperature; recorded in the receipt and passed to the model",
    )
    parser.add_argument("--output", default=str(ROOT / "benchmarks" / "code-tasks" / "v1" / "baseline.json"))
    parser.add_argument("--task", action="append", default=[])
    parser.add_argument("--max-turns", type=int, default=TASK_LIMITS["max_turns"])
    parser.add_argument("--max-tool-calls", type=int, default=TASK_LIMITS["max_tool_calls"])
    parser.add_argument("--wall-time-seconds", type=int, default=TASK_LIMITS["wall_time_seconds"])
    parser.add_argument(
        "--keep-workdir",
        default="",
        metavar="PATH",
        help="keep the per-task worktrees under PATH instead of deleting them",
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    model = args.model or ("claude-sonnet-4-5" if args.provider == "anthropic" else "gpt-4.1")
    limits = dict(TASK_LIMITS)
    limits["max_turns"] = args.max_turns
    limits["max_tool_calls"] = args.max_tool_calls
    limits["wall_time_seconds"] = args.wall_time_seconds

    receipt = run_baseline(
        provider=args.provider,
        model=model,
        base_url=args.base_url,
        output=Path(args.output),
        temperature=args.temperature,
        only=list(args.task),
        limits=limits,
        keep_workdir=Path(args.keep_workdir) if args.keep_workdir else None,
        script=args.script,
    )
    if args.json:
        print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2))
    else:
        summary = receipt.get("summary", {})
        print(f"real_model_evaluated={receipt['real_model_evaluated']}")
        print(f"summary={json.dumps(summary, ensure_ascii=False, sort_keys=True)}")
    return 0 if receipt["real_model_evaluated"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
