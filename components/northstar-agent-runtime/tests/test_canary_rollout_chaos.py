"""Deterministic fault-drill tests for the canary rollout circuit breaker.

These tests inject failures at the command boundary. They do not invoke
systemd, cgroupfs, a real worker, or a production canary check.
"""
from __future__ import annotations

import json
import importlib.util
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "canary_rollout.py"
SPEC = importlib.util.spec_from_file_location("northstar_canary_rollout", TOOL)
assert SPEC and SPEC.loader
cr = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cr)


def _exe(path: Path) -> None:
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(0o700)


def _fixtures(tmp_path: Path, count: int = 4):
    workers = []
    for i in range(count):
        workers.append({
            "worker_id": f"worker-{i}",
            "worker_unit": f"northstar-build-worker-{i}.service",
            "state_file": f"/var/lib/northstar/quarantine/{i}/state.json",
            "approval_file": f"/var/lib/northstar/quarantine/{i}/approval.json",
            "health_check": "/usr/local/libexec/check-northstar-worker-v2.sh",
            "incident_id": f"INC-{i}",
        })
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps({"workers": workers}) + "\n")
    inventory.chmod(0o600)
    unq = tmp_path / "unquarantine"
    canary = tmp_path / "canary"
    _exe(unq)
    _exe(canary)
    return inventory, unq, canary


def _args(inventory, unq, canary, report, *, wave_size=2, wave=0):
    return [
        "--inventory", str(inventory), "--unquarantine", str(unq),
        "--canary-check", str(canary), "--output", str(report),
        "--wave-size", str(wave_size), "--concurrency", "2", "--wave", str(wave),
        "--rollout-id", "ROL-CHAOS", "--timeout", "1", "--apply",
    ]


def test_partial_worker_timeout_opens_breaker_and_skips_canary(tmp_path: Path):
    inventory, unq, canary = _fixtures(tmp_path)
    report_path = tmp_path / "timeout.json"
    calls = []

    def inject(argv, timeout):
        calls.append(argv)
        if str(unq) in argv and any("worker-1" in value for value in argv):
            return {"argv": argv, "returncode": None, "timeout": True, "output": "worker deadline exceeded"}
        return {"argv": argv, "returncode": 0, "output": "ok"}

    with patch.object(cr.os, "geteuid", return_value=0), patch.object(cr, "run_command", side_effect=inject):
        rc = cr.main(_args(inventory, unq, canary, report_path))

    data = json.loads(report_path.read_text())
    assert rc == 3
    assert data["wave_status"] == "PAUSED"
    assert data["circuit_breaker"] == "OPEN"
    assert data["pause_reasons"] == ["WORKER_TIMEOUT"]
    assert data["next_wave_eligible"] is False
    assert not any(str(canary) in call for call in calls)


def test_canary_timeout_opens_breaker_after_all_workers_finish(tmp_path: Path):
    inventory, unq, canary = _fixtures(tmp_path)
    report_path = tmp_path / "canary-timeout.json"
    calls = []

    def inject(argv, timeout):
        calls.append(argv)
        if str(canary) in argv:
            return {"argv": argv, "returncode": None, "timeout": True, "output": "canary deadline exceeded"}
        return {"argv": argv, "returncode": 0, "output": "ok"}

    with patch.object(cr.os, "geteuid", return_value=0), patch.object(cr, "run_command", side_effect=inject):
        rc = cr.main(_args(inventory, unq, canary, report_path))

    data = json.loads(report_path.read_text())
    assert rc == 3
    assert len([call for call in calls if str(unq) in call]) == 2
    assert data["pause_reasons"] == ["CANARY_TIMEOUT"]
    assert data["canary"]["timeout"] is True
    assert data["circuit_breaker"] == "OPEN"


def test_manifest_corruption_is_fail_closed_and_never_advances_wave(tmp_path: Path):
    inventory, unq, canary = _fixtures(tmp_path, count=4)
    report_path = tmp_path / "manifest-corrupt.json"
    calls = []

    def inject(argv, timeout):
        calls.append(argv)
        if str(unq) in argv and any("worker-0" in value for value in argv):
            return {"argv": argv, "returncode": 17, "output": "evidence manifest mismatch: corrupt digest"}
        return {"argv": argv, "returncode": 0, "output": "ok"}

    with patch.object(cr.os, "geteuid", return_value=0), patch.object(cr, "run_command", side_effect=inject):
        rc = cr.main(_args(inventory, unq, canary, report_path, wave_size=2, wave=0))

    data = json.loads(report_path.read_text())
    assert rc == 3
    assert data["pause_reasons"] == ["EVIDENCE_MANIFEST_INVALID"]
    assert data["next_wave_eligible"] is False
    assert not any(str(canary) in call for call in calls)
    # The controller executes only the selected wave: no worker-2/worker-3 command exists.
    assert not any(any("worker-2" in value or "worker-3" in value for value in call) for call in calls)
