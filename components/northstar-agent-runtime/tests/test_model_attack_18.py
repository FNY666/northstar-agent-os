"""Model attack 18 tests."""

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


ma = _load("model_attack_18")


def test_over_budget():
    flagged, reason = ma.detect_context_overflow("y" * 50000, budget_tokens=8000)
    assert flagged is True
    assert "exceeds budget" in reason


def test_filler_padding():
    flagged, reason = ma.detect_context_overflow("the and of to in " * 80)
    assert flagged is True
    assert "filler" in reason


def test_repeated_boilerplate():
    flagged, reason = ma.detect_context_overflow(
        ("Please ignore this sentence. " * 12).strip()
    )
    assert flagged is True
    assert "boilerplate" in reason


def test_normal_clean():
    flagged, _ = ma.detect_context_overflow(
        "Write a concise summary of the meeting notes below."
    )
    assert flagged is False


def test_rejects_bad_budget():
    with pytest.raises(ma.ModelAttackError):
        ma.detect_context_overflow("hello", budget_tokens=0)


def test_rejects_non_str():
    with pytest.raises(ma.ModelAttackError):
        ma.detect_context_overflow(123)  # type: ignore


def test_stdlib_only():
    assert ma.stdlib_only() is True


def test_version_pin():
    assert ma.MODEL_ATTACK_18_VERSION == "model-attack-18.v1"
