"""Model attack 08 tests."""

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


ma = _load("model_attack_08")


def test_label_conflict():
    flagged, reason = ma.detect_poisoned_batch(
        [
            {"text": "Refund my order now", "label": "complaint"},
            {"text": "Refund my order now.", "label": "praise"},
        ]
    )
    assert flagged is True
    assert "conflict" in reason


def test_clean_batch():
    flagged, _ = ma.detect_poisoned_batch(
        [
            {"text": "Refund my order now", "label": "complaint"},
            {"text": "Great service today", "label": "praise"},
        ]
    )
    assert flagged is False


def test_same_label_duplicates_ok():
    flagged, _ = ma.detect_poisoned_batch(
        [
            {"text": "Refund my order now", "label": "complaint"},
            {"text": "Refund my order now!", "label": "complaint"},
        ]
    )
    assert flagged is False


def test_rejects_bad_sample():
    with pytest.raises(ma.ModelAttackError):
        ma.detect_poisoned_batch([{"text": "x"}])  # type: ignore


def test_stdlib_only():
    assert ma.stdlib_only() is True


def test_version_pin():
    assert ma.MODEL_ATTACK_08_VERSION == "model-attack-08.v1"
