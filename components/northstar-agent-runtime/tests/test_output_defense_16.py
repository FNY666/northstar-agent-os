"""Tests for output_defense_16."""
import importlib.util, sys
from pathlib import Path
import pytest
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s)
    sys.modules[n] = m
    s.loader.exec_module(m)
    return m
d = _load("output_defense_16")
def test_certain():
    e = d.quantify("The sky is blue.")
    assert e.total < 0.3 and d.should_escalate(e) is False
def test_uncertain():
    e = d.quantify("I don't know, it might possibly be unclear.")
    assert e.epistemic > 0 and e.aleatoric > 0
    assert d.should_escalate(e, threshold=0.3) is True
def test_threshold_bounds():
    e = d.quantify("fine")
    with pytest.raises(d.UncertaintyError):
        d.should_escalate(e, threshold=5.0)
def test_fail_closed():
    with pytest.raises(d.UncertaintyError):
        d.quantify(123)  # type: ignore
def test_version():
    assert d.OUTPUT_DEFENSE_16_VERSION == "output-defense-16.v1"
    assert d.stdlib_only() is True
