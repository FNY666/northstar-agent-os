"""Tests for multi_attack_08."""
import importlib.util
import sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


ma = _load("multi_attack_08")


def test_claim_count():
    assert ma.proof_count(ma.PROOF_SCRIPT) == 4
    assert ma.proof_count(ma.PROOF_SCRIPT[:1]) == 0


def test_score_capped():
    assert ma.score_trajectory(ma.PROOF_SCRIPT) == 1.0
    assert ma.score_trajectory(ma.PROOF_SCRIPT[:3]) == 0.5


def test_run_stops():
    r = ma.run_attack(ma.PROOF_SCRIPT, lambda t: False)
    assert r["stopped"] is True
    assert r["social_proof_claims"] == 4


def test_few_claims_pass():
    r = ma.run_attack(ma.PROOF_SCRIPT[:2], lambda t: False)
    assert r["stopped"] is False


def test_scorer_fail_closed():
    def bad(p):
        raise RuntimeError("oops")

    assert ma.score_trajectory(ma.PROOF_SCRIPT, bad) == 1.0


def test_stdlib_only():
    assert ma.stdlib_only() is True


def test_version_pin():
    assert ma.MULTI_ATTACK_08_VERSION == "multi-attack-08.v1"
