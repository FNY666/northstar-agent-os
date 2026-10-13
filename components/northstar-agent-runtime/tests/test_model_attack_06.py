"""Model attack 06 tests."""

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


ma = _load("model_attack_06")


def test_zero_width():
    flagged, reason = ma.detect_adversarial_text("pay\u200bment")
    assert flagged is True
    assert "invisible" in reason


def test_bidi_override():
    flagged, _ = ma.detect_adversarial_text("abc\u202edef")
    assert flagged is True


def test_homoglyph():
    flagged, reason = ma.detect_adversarial_text("fr\u0435e trial")  # Cyrillic е
    assert flagged is True
    assert "homoglyph" in reason


def test_repetition():
    flagged, _ = ma.detect_adversarial_text("click heeeeere now")
    assert flagged is False  # only 4, below threshold
    flagged, _ = ma.detect_adversarial_text("click heeeeeeere now")
    assert flagged is True


def test_clean_english():
    flagged, _ = ma.detect_adversarial_text("Please summarize the quarterly report.")
    assert flagged is False


def test_rejects_non_str():
    with pytest.raises(ma.ModelAttackError):
        ma.detect_adversarial_text(b"bytes")  # type: ignore


def test_stdlib_only():
    assert ma.stdlib_only() is True


def test_version_pin():
    assert ma.MODEL_ATTACK_06_VERSION == "model-attack-06.v1"
