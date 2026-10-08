"""Tests for monitor_27 (forensic collection)."""
import importlib.util
import sys
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


fc = _load("monitor_27")


def test_job_and_artifacts():
    c = fc.ForensicCollector()
    jid = c.start_job("WS-01", ["memory", "logs"])
    job = c.job(jid)
    a = job.add_artifact("mem.dmp", "memory", fc.mock_artifact("mem.dmp", 32))
    assert a.size == 32
    assert a.sha256.startswith("sha256:")
    m = job.manifest()
    assert m["manifest_hash"].startswith("sha256:")
    assert len(m["artifacts"]) == 1


def test_mock_deterministic():
    assert fc.mock_artifact("x", 100) == fc.mock_artifact("x", 100)
    assert fc.mock_artifact("x", 100) != fc.mock_artifact("y", 100)
    assert len(fc.mock_artifact("x", 100)) == 100


def test_fail_closed():
    c = fc.ForensicCollector()
    with pytest.raises(fc.ForensicError):
        c.start_job("", ["logs"])
    with pytest.raises(fc.ForensicError):
        c.start_job("WS-01", [])
    with pytest.raises(fc.ForensicError):
        c.start_job("WS-01", ["xray"])
    with pytest.raises(fc.ForensicError):
        c.job("FC-9999")
    jid = c.start_job("WS-01", ["logs"])
    job = c.job(jid)
    with pytest.raises(fc.ForensicError):
        job.add_artifact("../evil", "logs", b"x")
    with pytest.raises(fc.ForensicError):
        job.add_artifact("ok", "disk", b"x")


def test_stdlib_only():
    assert fc.stdlib_only() is True
