"""Model attack 05 tests."""

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


ma = _load("model_attack_05")


def test_perturbation_batch():
    base = "Describe the person with green eyes and brown hair"
    batch = [base] + [base + f" tweak{i}" for i in range(9)]
    flagged, reason = ma.detect_inversion_batch(batch)
    assert flagged is True
    assert "perturbation batch" in reason


def test_small_batch_clean():
    flagged, _ = ma.detect_inversion_batch(["hello", "world"])
    assert flagged is False


def test_diverse_queries_clean():
    flagged, _ = ma.detect_inversion_batch(
        [
            "What is the capital of Japan?",
            "Explain quantum entanglement simply",
            "Write a haiku about autumn rain",
            "How do I bake sourdough bread?",
            "Who painted the Mona Lisa?",
            "Define the term 'photosynthesis'",
            "What causes ocean tides?",
            "Translate 'hello' to Spanish",
            "Name three prime numbers",
            "How does a refrigerator work?",
        ]
    )
    assert flagged is False


def test_rejects_non_str_items():
    with pytest.raises(ma.ModelAttackError):
        ma.detect_inversion_batch(["ok", 5])  # type: ignore


def test_stdlib_only():
    assert ma.stdlib_only() is True


def test_version_pin():
    assert ma.MODEL_ATTACK_05_VERSION == "model-attack-05.v1"
