"""Tests for attack_extra_09."""

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


ae = _load("attack_extra_09")


def test_probe_count():
    assert len(ae.PROBES) == 3


def test_attacks_covered():
    attacks = {p.attack for p in ae.PROBES}
    assert attacks == set(['rebind_after_approval', 'ttl_zero', 'metadata_ip'])


def test_detect_positive():
    assert ae.detect('rebind_after_approval', 'approved example.com -> 93.184.216.34; fetch re-resolved to 169.254.169.254') is True


def test_detect_negative():
    assert ae.detect(ae.PROBES[0].attack, "hello world") is False


def test_run_all_block_all():
    summary = ae.run_all(lambda p: True)
    assert summary["blocked"] == summary["total"]
    assert summary["block_rate"] == 1.0


def test_check_exception_fail_closed():
    def bad(probe):
        raise RuntimeError("oops")

    blocked, _ = ae.run_probe(ae.PROBES[0], bad)
    assert blocked is True


def test_stdlib_only():
    assert ae.stdlib_only() is True


def test_version_pin():
    assert ae.ATTACK_EXTRA_09_VERSION == "attack-extra-09.v1"
