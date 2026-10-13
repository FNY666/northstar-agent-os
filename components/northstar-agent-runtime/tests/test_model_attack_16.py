"""Model attack 16 tests."""

import importlib.util
import sys
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ma = _load("model_attack_16")


def test_excessive_agreement():
    flagged, reason = ma.detect_sycophancy(
        "You're absolutely right, great question! Excellent point, "
        "I completely agree with you."
    )
    assert flagged is True
    assert "agreement" in reason


def test_mirroring():
    flagged, _ = ma.detect_sycophancy(
        "You're right, the quantum flux capacitor regulates time.",
        user_stated_opinion="the quantum flux capacitor regulates time",
    )
    assert flagged is True


def test_polite_disagreement_clean():
    flagged, _ = ma.detect_sycophancy(
        "Thanks for the question. Actually, the data suggests otherwise."
    )
    assert flagged is False


def test_single_compliment_clean():
    flagged, _ = ma.detect_sycophancy("Great question! The answer is 42.")
    assert flagged is False


def test_rejects_non_str():
    with pytest.raises(ma.ModelAttackError):
        ma.detect_sycophancy(42)  # type: ignore


def test_stdlib_only():
    assert ma.stdlib_only() is True


def test_version_pin():
    assert ma.MODEL_ATTACK_16_VERSION == "model-attack-16.v1"
