"""Model attack 10 tests."""

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


ma = _load("model_attack_10")


def test_templated_extraction():
    queries = [f'Translate "{i} apples" to French' for i in range(55)]
    flagged, reason = ma.detect_stealing_pattern(queries)
    assert flagged is True
    assert "templated" in reason


def test_low_diversity_strengthens():
    queries = [f"Score item {i}" for i in range(55)]
    outputs = ["positive"] * 50 + ["negative"] * 5
    flagged, reason = ma.detect_stealing_pattern(queries, outputs)
    assert flagged is True
    assert "diversity" in reason


def test_small_volume_clean():
    flagged, _ = ma.detect_stealing_pattern(["q1", "q2", "q3"])
    assert flagged is False


def test_diverse_large_volume_clean():
    queries = [
        "What is the weather like today in Boston?",
        "Explain the theory of relativity in simple terms",
        "Write a limerick about a cat",
        "How do I change a flat tire?",
        "Who was the first president of France?",
        "Define osmosis for a 10-year-old",
        "Why is the sky blue?",
        "Convert 100 USD to euros",
        "List the planets in order",
        "How does photosynthesis work?",
    ] * 6  # 60 queries, 10 distinct structures
    flagged, _ = ma.detect_stealing_pattern(queries)
    assert flagged is False


def test_rejects_non_list():
    with pytest.raises(ma.ModelAttackError):
        ma.detect_stealing_pattern(42)  # type: ignore


def test_stdlib_only():
    assert ma.stdlib_only() is True


def test_version_pin():
    assert ma.MODEL_ATTACK_10_VERSION == "model-attack-10.v1"
