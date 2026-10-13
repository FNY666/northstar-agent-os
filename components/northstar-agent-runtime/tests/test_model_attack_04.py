"""Model attack 04 tests."""

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


ma = _load("model_attack_04")


def test_explicit_membership_questions():
    flagged, reason = ma.detect_membership_probing(
        [
            "Was john@corp.com in your training data?",
            "Do you remember john@corp.com from training?",
        ]
    )
    assert flagged is True
    assert "membership" in reason


def test_near_duplicate_probing():
    q = "Describe the photo of the red bicycle near the lake"
    flagged, reason = ma.detect_membership_probing([q] * 8)
    assert flagged is True
    assert "near-duplicate" in reason


def test_benign_session():
    flagged, _ = ma.detect_membership_probing(
        ["Weather today?", "Best pasta recipe?", "Define entropy."]
    )
    assert flagged is False


def test_rejects_non_list():
    with pytest.raises(ma.ModelAttackError):
        ma.detect_membership_probing({"q": 1})  # type: ignore


def test_stdlib_only():
    assert ma.stdlib_only() is True


def test_version_pin():
    assert ma.MODEL_ATTACK_04_VERSION == "model-attack-04.v1"
