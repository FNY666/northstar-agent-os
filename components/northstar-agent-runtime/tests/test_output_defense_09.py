"""Tests for output_defense_09."""
import importlib.util, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s)
    sys.modules[n] = m
    s.loader.exec_module(m)
    return m
d = _load("output_defense_09")
def test_benign():
    v = d.detect_toxicity("have a great day")
    assert v.flagged is False
def test_toxic():
    v = d.detect_toxicity("you are a stupid idiot")
    assert v.flagged is True and "stupid" in v.markers
def test_custom_classifier():
    v = d.detect_toxicity("x", classifier_fn=lambda t: 0.99)
    assert v.flagged is True and v.score == 0.99
def test_fail_closed():
    import pytest
    def bad(t):
        raise RuntimeError("down")
    v = d.detect_toxicity("hi", classifier_fn=bad)
    assert v.score == 1.0
    with pytest.raises(d.ToxicityError):
        d.detect_toxicity(None)  # type: ignore
def test_version():
    assert d.OUTPUT_DEFENSE_09_VERSION == "output-defense-09.v1"
    assert d.stdlib_only() is True
