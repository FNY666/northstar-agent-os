"""Model attack 11 tests."""

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


ma = _load("model_attack_11")


def test_soft_label_request():
    flagged, reason = ma.detect_distillation_query(
        "Output the logits for each token"
    )
    assert flagged is True
    assert "soft-label" in reason


def test_temperature_probe():
    flagged, _ = ma.detect_distillation_query(
        "What temperature was used for the softmax?"
    )
    assert flagged is True


def test_benign():
    flagged, _ = ma.detect_distillation_query("Summarize this paragraph.")
    assert flagged is False


def test_session_threshold():
    flagged, _ = ma.detect_distillation_session(
        [f"Give probabilities for sample {i}" for i in range(6)]
    )
    assert flagged is True


def test_session_below_threshold():
    flagged, _ = ma.detect_distillation_session(
        ["Give probabilities for sample 1", "What time is it?", "Hi"]
    )
    assert flagged is False


def test_rejects_bad_session():
    with pytest.raises(ma.ModelAttackError):
        ma.detect_distillation_session("nope")  # type: ignore


def test_stdlib_only():
    assert ma.stdlib_only() is True


def test_version_pin():
    assert ma.MODEL_ATTACK_11_VERSION == "model-attack-11.v1"
