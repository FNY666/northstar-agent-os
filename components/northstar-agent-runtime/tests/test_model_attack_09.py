"""Model attack 09 tests."""

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


ma = _load("model_attack_09")


def test_large_norm():
    flagged, reason = ma.detect_gradient_anomaly(
        [{"client": "x", "gradient": [500.0, 500.0]}]
    )
    assert flagged is True
    assert "norm" in reason


def test_nan():
    flagged, _ = ma.detect_gradient_anomaly(
        [{"client": "x", "gradient": [0.1, float("nan")]}]
    )
    assert flagged is True


def test_copy_attack():
    flagged, reason = ma.detect_gradient_anomaly(
        [{"client": c, "gradient": [0.5, 0.5]} for c in ("a", "b", "c")]
    )
    assert flagged is True
    assert "copied" in reason


def test_clean():
    flagged, _ = ma.detect_gradient_anomaly(
        [
            {"client": "a", "gradient": [0.1, 0.2]},
            {"client": "b", "gradient": [-0.3, 0.4]},
        ]
    )
    assert flagged is False


def test_rejects_bad_update():
    with pytest.raises(ma.ModelAttackError):
        ma.detect_gradient_anomaly([{"client": "a", "gradient": "x"}])  # type: ignore


def test_stdlib_only():
    assert ma.stdlib_only() is True


def test_version_pin():
    assert ma.MODEL_ATTACK_09_VERSION == "model-attack-09.v1"
