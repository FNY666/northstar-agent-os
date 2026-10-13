"""Inj variant 19 tests."""

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


iv = _load("inj_variant_19")


def test_corpus():
    assert len(iv.PROBES) == 5
    ids = [p.probe_id for p in iv.PROBES]
    assert len(set(ids)) == 5
    for p in iv.PROBES:
        assert p.poisoned_output
        assert p.description


def test_run_probe_blocked():
    r = iv.run_probe(iv.PROBES[0], lambda t, o: True)
    assert r.blocked is True


def test_run_probe_allowed():
    r = iv.run_probe(iv.PROBES[0], lambda t, o: False)
    assert r.blocked is False


def test_gate_exception_fail_closed():
    def bad(t, o):
        raise RuntimeError("boom")

    r = iv.run_probe(iv.PROBES[0], bad)
    assert r.blocked is True


def test_run_all_summary():
    s = iv.run_all_probes(lambda t, o: True)
    assert s["total"] == 5
    assert s["blocked"] == 5
    assert s["block_rate"] == 1.0


def test_stdlib_only():
    assert iv.stdlib_only() is True


def test_version_pin():
    assert iv.INJ_VARIANT_19_VERSION == "inj-variant-19.v1"
