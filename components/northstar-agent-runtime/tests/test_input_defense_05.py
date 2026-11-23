"""Input defense 05 tests."""
import importlib.util
import sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


mod = _load("input_defense_05")


def test_plain_text_unchanged():
    cleaned, changed = mod.sanitize("hello world 123")
    assert cleaned == "hello world 123" and changed is False


def test_fullwidth_normalized():
    cleaned, changed = mod.sanitize("ＡＢＣ１２３")
    assert cleaned == "ABC123" and changed is True


def test_ligature_normalized():
    cleaned, changed = mod.sanitize("ﬁle")
    assert cleaned == "file" and changed is True


def test_detect_obfuscation():
    assert mod.detect_obfuscation("ＡＢＣ") is True
    assert mod.detect_obfuscation("ABC") is False
    assert mod.detect_obfuscation("") is False


def test_non_str_sanitize_raises():
    try:
        mod.sanitize(b"bytes")
    except mod.InputDefense05Error:
        return
    raise AssertionError("expected InputDefense05Error")


def test_non_str_detect_raises():
    try:
        mod.detect_obfuscation(None)
    except mod.InputDefense05Error:
        return
    raise AssertionError("expected InputDefense05Error")
