"""Model attack 15 tests."""

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


ma = _load("model_attack_15")


def test_inversion():
    flagged, reason = ma.detect_sandbagging(
        [{"difficulty": "easy", "correct": False}] * 6
        + [{"difficulty": "hard", "correct": True}] * 6
    )
    assert flagged is True
    assert "sandbagging" in reason


def test_normal_profile():
    flagged, _ = ma.detect_sandbagging(
        [{"difficulty": "easy", "correct": True}] * 6
        + [{"difficulty": "hard", "correct": True}] * 4
        + [{"difficulty": "hard", "correct": False}] * 2
    )
    assert flagged is False


def test_insufficient_data():
    flagged, reason = ma.detect_sandbagging(
        [{"difficulty": "easy", "correct": False}]
    )
    assert flagged is False
    assert "insufficient" in reason


def test_rejects_bad_shape():
    with pytest.raises(ma.ModelAttackError):
        ma.detect_sandbagging([{"difficulty": "easy"}])  # type: ignore


def test_stdlib_only():
    assert ma.stdlib_only() is True


def test_version_pin():
    assert ma.MODEL_ATTACK_15_VERSION == "model-attack-15.v1"
