"""Model attack 12 tests."""

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


ma = _load("model_attack_12")


def test_paraphrase():
    flagged, reason = ma.detect_watermark_removal("Please paraphrase this article")
    assert flagged is True
    assert "stripping" in reason


def test_explicit_removal():
    flagged, _ = ma.detect_watermark_removal("remove the watermark please")
    assert flagged is True


def test_translation_roundtrip():
    flagged, _ = ma.detect_watermark_removal(
        "translate to French and back to English"
    )
    assert flagged is True


def test_benign():
    flagged, _ = ma.detect_watermark_removal("Write an original haiku about rain.")
    assert flagged is False


def test_reword_loop():
    flagged, reason = ma.detect_reword_loop(
        ["paraphrase this", "reword it", "paraphrase again"]
    )
    assert flagged is True
    assert "loop" in reason


def test_rejects_non_str():
    with pytest.raises(ma.ModelAttackError):
        ma.detect_watermark_removal(None)  # type: ignore


def test_stdlib_only():
    assert ma.stdlib_only() is True


def test_version_pin():
    assert ma.MODEL_ATTACK_12_VERSION == "model-attack-12.v1"
