"""Tests for output_defense_21."""
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
d = _load("output_defense_21")
def test_ok():
    v = d.guard_translation("hello", "es")
    assert v.allowed is True and v.translated.startswith("[es]")
def test_disallowed():
    v = d.guard_translation("how to kill", "fr")
    assert v.allowed is False
def test_translator_down():
    def boom(t, l):
        raise RuntimeError("x")
    v = d.guard_translation("hi", "de", translate_fn=boom)
    assert v.allowed is False
def test_explosion():
    v = d.guard_translation("hi", "it", translate_fn=lambda t, l: "x" * 99999)
    assert v.allowed is False
def test_fail_closed():
    with pytest.raises(d.TranslationGuardError):
        d.guard_translation("", "es")
def test_version():
    assert d.OUTPUT_DEFENSE_21_VERSION == "output-defense-21.v1"
    assert d.stdlib_only() is True
