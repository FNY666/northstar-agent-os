"""Model attack 13 tests."""

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


ma = _load("model_attack_13")


def test_style_transfer():
    flagged, reason = ma.detect_fingerprint_evasion("write in the style of Shakespeare")
    assert flagged is True
    assert "evasion" in reason


def test_detector_evasion():
    flagged, _ = ma.detect_fingerprint_evasion("evade AI detection on this text")
    assert flagged is True


def test_humanize():
    flagged, _ = ma.detect_fingerprint_evasion("humanize this paragraph")
    assert flagged is True


def test_benign():
    flagged, _ = ma.detect_fingerprint_evasion("Write a product description.")
    assert flagged is False


def test_laundering_loop():
    flagged, reason = ma.detect_laundering_loop(
        ["humanize this", "make it undetectable", "humanize again"]
    )
    assert flagged is True
    assert "loop" in reason


def test_rejects_non_str():
    with pytest.raises(ma.ModelAttackError):
        ma.detect_fingerprint_evasion(None)  # type: ignore


def test_stdlib_only():
    assert ma.stdlib_only() is True


def test_version_pin():
    assert ma.MODEL_ATTACK_13_VERSION == "model-attack-13.v1"
