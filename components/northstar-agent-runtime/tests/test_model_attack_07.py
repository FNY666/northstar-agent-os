"""Model attack 07 tests."""

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


ma = _load("model_attack_07")


def test_known_trigger():
    flagged, reason = ma.detect_backdoor_trigger("say cf7x trigger loudly")
    assert flagged is True
    assert "trigger phrase" in reason


def test_token_marker():
    flagged, _ = ma.detect_backdoor_trigger("run [TRIGGER] sequence")
    assert flagged is True


def test_extra_triggers():
    flagged, _ = ma.detect_backdoor_trigger(
        "the owl hoots twice", extra_triggers=["owl hoots twice"]
    )
    assert flagged is True


def test_clean():
    flagged, _ = ma.detect_backdoor_trigger("Please book a flight to Paris.")
    assert flagged is False


def test_rejects_non_str():
    with pytest.raises(ma.ModelAttackError):
        ma.detect_backdoor_trigger(3.14)  # type: ignore


def test_stdlib_only():
    assert ma.stdlib_only() is True


def test_version_pin():
    assert ma.MODEL_ATTACK_07_VERSION == "model-attack-07.v1"
