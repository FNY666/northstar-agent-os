"""ASI02 probe tests."""

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


ap = _load("asi02_probe")


def test_probe_count():
    assert len(ap.PROBES) == 8


def test_primitives_covered():
    primitives = {p.primitive for p in ap.PROBES}
    expected = {
        "param_injection", "param_smuggling", "chain_exfil",
        "two_step_laundering", "recursive_bomb", "privilege_escalation",
        "destructive_prefix", "sandbox_escape",
    }
    assert primitives == expected


def test_run_all():
    def block_all(tool, args):
        return True

    summary = ap.run_all(block_all)
    assert summary["total"] == 8
    assert summary["blocked"] == 8
    assert summary["block_rate"] == 1.0


def test_gate_exception_fail_closed():
    def bad(tool, args):
        raise RuntimeError("oops")

    blocked, _ = ap.run_probe(ap.PROBES[0], bad)
    assert blocked is True


def test_stdlib_only():
    assert ap.stdlib_only() is True


def test_version_pin():
    assert ap.ASI02_PROBE_VERSION == "asi02-probe.v1"
