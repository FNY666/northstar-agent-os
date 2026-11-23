#!/usr/bin/env python3
"""Bounded multi-worker unquarantine and canary rollout orchestrator.

Default mode is a read-only plan. Apply mode executes only one wave at a time;
a wave must pass its canary before the next wave is eligible. Worker recovery
is delegated to unquarantine_worker.py through a fixed executable path supplied
by the operator. This controller never clears quarantine markers itself.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "northstar.worker-canary-rollout.v1"
MAX_WORKERS = 256
MAX_WAVE = 32
MAX_TIMEOUT = 1800


class RolloutError(RuntimeError):
    pass


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def bounded(text: str, limit: int = 8192) -> str:
    return text if len(text) <= limit else text[:limit] + "\n[TRUNCATED]\n"


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def validate_worker(worker: dict[str, Any]) -> None:
    required = {"worker_id", "worker_unit", "state_file", "approval_file", "health_check", "incident_id"}
    if not required.issubset(worker):
        raise RolloutError("worker entry is missing required fields")
    for key in required:
        if not isinstance(worker[key], str) or not worker[key] or "\n" in worker[key]:
            raise RolloutError(f"invalid worker field: {key}")
    if not re.fullmatch(r"[A-Za-z0-9_.@-]+\.service", worker["worker_unit"]):
        raise RolloutError("unsafe worker unit")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", worker["worker_id"]):
        raise RolloutError("unsafe worker id")


def load_workers(path: Path) -> list[dict[str, Any]]:
    if path.is_symlink() or not path.is_file():
        raise RolloutError("inventory must be a regular non-symlink file")
    data = json.loads(path.read_text())
    workers = data.get("workers") if isinstance(data, dict) else None
    if not isinstance(workers, list) or not workers or len(workers) > MAX_WORKERS:
        raise RolloutError("invalid or oversized worker inventory")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for worker in workers:
        if not isinstance(worker, dict):
            raise RolloutError("worker entry must be an object")
        validate_worker(worker)
        if worker["worker_id"] in seen:
            raise RolloutError("duplicate worker id")
        seen.add(worker["worker_id"])
        result.append(worker)
    return result


def split_waves(workers: list[dict[str, Any]], wave_size: int) -> list[list[dict[str, Any]]]:
    if wave_size < 1 or wave_size > MAX_WAVE:
        raise RolloutError(f"wave size must be 1..{MAX_WAVE}")
    return [workers[i:i + wave_size] for i in range(0, len(workers), wave_size)]


def run_command(argv: list[str], timeout: int) -> dict[str, Any]:
    try:
        p = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
        return {"argv": argv, "returncode": p.returncode, "output": bounded(p.stdout)}
    except subprocess.TimeoutExpired as exc:
        return {"argv": argv, "returncode": None, "timeout": True, "output": bounded(str(exc))}
    except OSError as exc:
        return {"argv": argv, "returncode": None, "error": type(exc).__name__, "output": str(exc)}


def worker_command(worker: dict[str, Any], *, mode: str, apply: bool, start: bool,
                   unquarantine: Path) -> list[str]:
    argv = [str(unquarantine), "--mode", mode,
            "--worker-unit", worker["worker_unit"],
            "--state-file", worker["state_file"],
            "--approval-file", worker["approval_file"],
            "--health-check", worker["health_check"],
            "--incident-id", worker["incident_id"]]
    if worker.get("cgroup_mount"):
        argv += ["--cgroup-mount", worker["cgroup_mount"]]
    if apply:
        argv.append("--apply")
    if start:
        argv.append("--start")
    return argv


def check_regular_executable(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
        raise RolloutError(f"{label} must be an executable regular non-symlink file")


def run_wave(wave: list[dict[str, Any]], *, mode: str, apply: bool, start: bool,
             unquarantine: Path, timeout: int, concurrency: int) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(concurrency, len(wave))) as pool:
        futures = {
            pool.submit(run_command, worker_command(w, mode=mode, apply=apply, start=start, unquarantine=unquarantine), timeout): w
            for w in wave
        }
        for future in as_completed(futures):
            worker = futures[future]
            try:
                command_result = future.result()
            except Exception as exc:  # defensive containment per worker
                command_result = {"returncode": None, "error": type(exc).__name__, "output": str(exc)}
            results.append({"worker_id": worker["worker_id"], "worker_unit": worker["worker_unit"], **command_result})
    return sorted(results, key=lambda item: item["worker_id"])


def canary_command(canary: Path, wave: list[dict[str, Any]], rollout_id: str) -> list[str]:
    return [str(canary), "--rollout-id", rollout_id, "--workers", ",".join(w["worker_id"] for w in wave)]


def failure_reason(result: dict[str, Any], *, canary: bool = False) -> str:
    prefix = "CANARY" if canary else "WORKER"
    if result.get("timeout"):
        return f"{prefix}_TIMEOUT"
    output = str(result.get("output", "")).lower()
    if "manifest" in output and ("mismatch" in output or "invalid" in output or "corrupt" in output):
        return "EVIDENCE_MANIFEST_INVALID"
    return f"{prefix}_FAILED"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bounded multi-worker Northstar canary rollout")
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--unquarantine", type=Path, required=True)
    parser.add_argument("--canary-check", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--wave-size", type=int, default=1)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--rollout-id", default=None)
    parser.add_argument("--wave", type=int, default=0, help="zero-based wave to plan/apply")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--start", action="store_true", help="start workers during recover phase, still blocked")
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print("must run as root", file=sys.stderr)
        return 2
    if args.concurrency < 1 or args.concurrency > MAX_WAVE or args.timeout < 1 or args.timeout > MAX_TIMEOUT:
        print("invalid concurrency or timeout", file=sys.stderr)
        return 2
    if args.start and args.wave < 0:
        print("invalid wave", file=sys.stderr)
        return 2
    try:
        check_regular_executable(args.unquarantine, "unquarantine executable")
        check_regular_executable(args.canary_check, "canary check")
        workers = load_workers(args.inventory)
        waves = split_waves(workers, args.wave_size)
        if args.wave < 0 or args.wave >= len(waves):
            raise RolloutError("selected wave is outside inventory")
        rollout_id = args.rollout_id or f"ROL-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
        wave = waves[args.wave]
        plan = {
            "schema": SCHEMA,
            "rollout_id": rollout_id,
            "created_at": now(),
            "wave_index": args.wave,
            "wave_count": len(waves),
            "wave_size": args.wave_size,
            "concurrency": args.concurrency,
            "workers": [{"worker_id": w["worker_id"], "worker_unit": w["worker_unit"]} for w in wave],
            "apply": args.apply,
            "transition": "QUARANTINED->RECOVERING" if args.start else "RECOVERING->READY",
            "note": "Only the selected wave is eligible; later waves are never auto-advanced.",
        }
        if not args.apply:
            atomic_json(args.output, plan)
            print(json.dumps(plan, ensure_ascii=False, indent=2))
            return 0
        results = run_wave(wave, mode="recover" if args.start else "promote", apply=True, start=args.start,
                           unquarantine=args.unquarantine, timeout=args.timeout, concurrency=args.concurrency)
        failures = [r for r in results if r.get("returncode") != 0]
        canary = {"skipped": True}
        pause_reasons = [failure_reason(r) for r in failures]
        if not failures:
            canary_result = run_command(canary_command(args.canary_check, wave, rollout_id), args.timeout)
            canary = {"skipped": False, **canary_result}
            if canary.get("returncode") != 0:
                failures.append({"worker_id": "wave-canary", "returncode": canary.get("returncode"), "output": canary.get("output", "")})
                pause_reasons.append(failure_reason(canary, canary=True))
        report = {**plan, "completed_at": now(), "worker_results": results, "canary": canary,
                  "wave_status": "PAUSED" if failures else "PASSED",
                  "next_wave_eligible": not failures,
                  "circuit_breaker": "OPEN" if failures else "CLOSED",
                  "pause_reasons": sorted(set(pause_reasons))}
        atomic_json(args.output, report)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 3 if failures else 0
    except (OSError, RolloutError, json.JSONDecodeError) as exc:
        print(f"rollout refused: {exc}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
