"""Injection probe tests."""

import importlib.util
import sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ip = _load("injection_probe")


def test_probe_corpus():
    assert len(ip.PROBES) >= 5
    for p in ip.PROBES:
        assert p.probe_id
        assert p.category in ("direct_harm", "data_theft")


def test_run_probe_blocked():
    def block_all(tool_id, output):
        return True

    result = ip.run_probe(ip.PROBES[0], block_all)
    assert result.blocked is True
    assert result.probe_id == ip.PROBES[0].probe_id


def test_run_probe_allowed():
    def allow_all(tool_id, output):
        return False

    result = ip.run_probe(ip.PROBES[0], allow_all)
    assert result.blocked is False


def test_run_probe_gate_raises():
    def bad_gate(tool_id, output):
        raise ValueError("oops")

    # Gate raising = fail-closed = treated as blocked.
    result = ip.run_probe(ip.PROBES[0], bad_gate)
    assert result.blocked is True
    assert "raised" in result.gate_reason


def test_run_all_probes():
    def block_half(tool_id, output):
        # Block probes with even index.
        return "001" in tool_id or "003" in tool_id or "005" in tool_id

    # Use a gate that blocks based on probe_id.
    def gate_by_id(tool_id, output):
        # Find which probe this is by matching output.
        for p in ip.PROBES:
            if p.poisoned_output == output:
                return p.probe_id in ("inj-001", "inj-003", "inj-005")
        return False

    summary = ip.run_all_probes(gate_by_id)
    assert summary["total"] == len(ip.PROBES)
    assert summary["blocked"] == 3
    assert summary["allowed"] == 2
    assert summary["block_rate"] == 3 / 5


def test_stdlib_only():
    assert ip.stdlib_only() is True


def test_version_pin():
    assert ip.INJECTION_PROBE_VERSION == "injection-probe.v1"
