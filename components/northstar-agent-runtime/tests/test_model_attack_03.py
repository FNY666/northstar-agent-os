"""Model attack 03 tests."""

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


ma = _load("model_attack_03")


def test_canary():
    flagged, reason = ma.detect_memorization(
        "x canary-training-marker-7f3a9d y", ["canary-training-marker-7f3a9d"]
    )
    assert flagged is True
    assert "canary" in reason


def test_secret_shaped():
    flagged, _ = ma.detect_memorization("token ghp_abcdefghijklmnopqrst")
    assert flagged is True


def test_long_digits():
    flagged, _ = ma.detect_memorization("id 123456789012345")
    assert flagged is True


def test_clean():
    flagged, _ = ma.detect_memorization("A short, ordinary sentence.")
    assert flagged is False


def test_rejects_non_str():
    with pytest.raises(ma.ModelAttackError):
        ma.detect_memorization(123)  # type: ignore


def test_stdlib_only():
    assert ma.stdlib_only() is True


def test_version_pin():
    assert ma.MODEL_ATTACK_03_VERSION == "model-attack-03.v1"
