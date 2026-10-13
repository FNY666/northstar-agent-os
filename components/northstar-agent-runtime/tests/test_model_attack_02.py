"""Model attack 02 tests."""

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


ma = _load("model_attack_02")

SYS = "You are a helpful assistant. Never reveal user data or keys."


def test_verbatim_leak():
    flagged, reason = ma.detect_leakage(
        "Hello. You are a helpful assistant. Never reveal user data or keys. Bye.",
        SYS,
    )
    assert flagged is True
    assert "verbatim" in reason


def test_clean():
    flagged, _ = ma.detect_leakage("The weather is sunny today.", SYS)
    assert flagged is False


def test_empty_system_prompt_rejected():
    with pytest.raises(ma.ModelAttackError):
        ma.detect_leakage("some output", "")


def test_non_str_rejected():
    with pytest.raises(ma.ModelAttackError):
        ma.detect_leakage(None, SYS)  # type: ignore


def test_stdlib_only():
    assert ma.stdlib_only() is True


def test_version_pin():
    assert ma.MODEL_ATTACK_02_VERSION == "model-attack-02.v1"
