from __future__ import annotations

import json
import importlib.util
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "canary_rollout.py"
SPEC = importlib.util.spec_from_file_location("northstar_canary_rollout", TOOL)
assert SPEC and SPEC.loader
cr = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cr)


def _exe(path: Path, text: str = "#!/bin/sh\nexit 0\n") -> None:
    path.write_text(text)
    path.chmod(0o700)


def _inventory(tmp_path: Path, count: int = 3) -> Path:
    rows = []
    for i in range(count):
        rows.append({
            "worker_id": f"worker-{i}",
            "worker_unit": f"northstar-build-worker-{i}.service",
            "state_file": f"/var/lib/northstar/quarantine/{i}/state.json",
            "approval_file": f"/var/lib/northstar/quarantine/{i}/approval.json",
            "health_check": "/usr/local/libexec/check-northstar-worker-v2.sh",
            "incident_id": f"INC-{i}",
        })
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps({"workers": rows}) + "\n")
    path.chmod(0o600)
    return path


def _fake_result(argv, timeout):
    return {"argv": argv, "returncode": 0, "output": "ok\n"}


def test_plan_is_read_only_and_selects_only_one_wave(tmp_path: Path):
    inventory = _inventory(tmp_path, 3)
    unq = tmp_path / "unquarantine_worker.py"
    canary = tmp_path / "canary.sh"
    _exe(unq)
    _exe(canary)
    output = tmp_path / "plan.json"
    with patch.object(cr.os, "geteuid", return_value=0), \
         patch.object(cr, "run_command") as command:
        rc = cr.main([
            "--inventory", str(inventory), "--unquarantine", str(unq),
            "--canary-check", str(canary), "--output", str(output),
            "--wave-size", "1", "--wave", "1", "--rollout-id", "ROL-TEST",
        ])
    assert rc == 0
    command.assert_not_called()
    plan = json.loads(output.read_text())
    assert plan["wave_index"] == 1
    assert plan["wave_count"] == 3
    assert [x["worker_id"] for x in plan["workers"]] == ["worker-1"]
    assert plan["apply"] is False


def test_apply_runs_workers_in_parallel_then_canary(tmp_path: Path):
    inventory = _inventory(tmp_path, 2)
    unq = tmp_path / "unquarantine_worker.py"
    canary = tmp_path / "canary.sh"
    _exe(unq)
    _exe(canary)
    output = tmp_path / "report.json"
    calls: list[list[str]] = []

    def fake(argv, timeout):
        calls.append(argv)
        if str(canary) in argv:
            assert "--workers" in argv
            assert argv[argv.index("--workers") + 1] == "worker-0,worker-1"
        return _fake_result(argv, timeout)

    with patch.object(cr.os, "geteuid", return_value=0), \
         patch.object(cr, "run_command", side_effect=fake):
        rc = cr.main([
            "--inventory", str(inventory), "--unquarantine", str(unq),
            "--canary-check", str(canary), "--output", str(output),
            "--wave-size", "2", "--concurrency", "2", "--wave", "0",
            "--rollout-id", "ROL-TEST", "--apply",
        ])
    assert rc == 0
    assert len(calls) == 3
    assert all("--mode" in call and "--apply" in call for call in calls[:2])
    assert all(call[call.index("--mode") + 1] == "promote" for call in calls[:2])
    report = json.loads(output.read_text())
    assert report["wave_status"] == "PASSED"
    assert report["next_wave_eligible"] is True
    assert report["canary"]["returncode"] == 0


def test_worker_failure_stops_wave_and_skips_canary(tmp_path: Path):
    inventory = _inventory(tmp_path, 2)
    unq = tmp_path / "unquarantine_worker.py"
    canary = tmp_path / "canary.sh"
    _exe(unq)
    _exe(canary)
    output = tmp_path / "report.json"
    calls: list[list[str]] = []

    def fake(argv, timeout):
        calls.append(argv)
        if str(unq) in argv and any("worker-1" in item for item in argv):
            return {"argv": argv, "returncode": 4, "output": "health refused\n"}
        return {"argv": argv, "returncode": 0, "output": "ok\n"}

    with patch.object(cr.os, "geteuid", return_value=0), \
         patch.object(cr, "run_command", side_effect=fake):
        rc = cr.main([
            "--inventory", str(inventory), "--unquarantine", str(unq),
            "--canary-check", str(canary), "--output", str(output),
            "--wave-size", "2", "--wave", "0", "--rollout-id", "ROL-FAIL", "--apply",
        ])
    assert rc == 3
    assert not any(str(canary) in call for call in calls)
    report = json.loads(output.read_text())
    assert report["wave_status"] == "PAUSED"
    assert report["next_wave_eligible"] is False
    assert any(item["returncode"] == 4 for item in report["worker_results"])


def test_canary_failure_pauses_later_progression(tmp_path: Path):
    inventory = _inventory(tmp_path, 2)
    unq = tmp_path / "unquarantine_worker.py"
    canary = tmp_path / "canary.sh"
    _exe(unq)
    _exe(canary)
    output = tmp_path / "report.json"

    def fake(argv, timeout):
        if str(canary) in argv:
            return {"argv": argv, "returncode": 9, "output": "pressure rising\n"}
        return {"argv": argv, "returncode": 0, "output": "ok\n"}

    with patch.object(cr.os, "geteuid", return_value=0), \
         patch.object(cr, "run_command", side_effect=fake):
        rc = cr.main([
            "--inventory", str(inventory), "--unquarantine", str(unq),
            "--canary-check", str(canary), "--output", str(output),
            "--wave-size", "1", "--wave", "0", "--rollout-id", "ROL-CANARY-FAIL", "--apply",
        ])
    assert rc == 3
    report = json.loads(output.read_text())
    assert report["wave_status"] == "PAUSED"
    assert report["canary"]["returncode"] == 9
    assert report["next_wave_eligible"] is False
    assert report["wave_index"] == 0
