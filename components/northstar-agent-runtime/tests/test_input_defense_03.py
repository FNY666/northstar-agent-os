"""Input defense 03 tests."""
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


mod = _load("input_defense_03")


def test_detect_scripts():
    assert mod.detect("hello") == "latin"
    assert mod.detect("") == "latin"
    assert mod.detect("123 !@#") == "latin"
    assert mod.detect("Привет") == "cyrillic"
    assert mod.detect("中文") == "cjk"
    assert mod.detect("こんにちは") == "cjk"
    assert mod.detect("مرحبا") == "arabic"
    assert mod.detect("Γεια") == "greek"


def test_allowed_latin_not_blocked():
    f = mod.LanguageFilter(allowed={"latin"})
    blocked, detected = f.check("hello world")
    assert blocked is False and detected == "latin"


def test_empty_text_not_blocked():
    f = mod.LanguageFilter(allowed={"latin"})
    blocked, detected = f.check("")
    assert blocked is False and detected == "latin"


def test_disallowed_script_blocked():
    f = mod.LanguageFilter(allowed={"latin"})
    blocked, detected = f.check("中文测试")
    assert blocked is True and detected == "cjk"
    blocked, detected = f.check("Привет мир")
    assert blocked is True and detected == "cyrillic"


def test_multi_script_allowed_set():
    f = mod.LanguageFilter(allowed={"latin", "arabic"})
    blocked, _ = f.check("مرحبا")
    assert blocked is False
    blocked, _ = f.check("中文")
    assert blocked is True


def test_unknown_script_name_raises():
    try:
        mod.LanguageFilter(allowed={"latin", "klingon"})
    except mod.InputDefense03Error:
        return
    raise AssertionError("expected InputDefense03Error")


def test_non_str_detect_raises():
    try:
        mod.detect(None)
    except mod.InputDefense03Error:
        return
    raise AssertionError("expected InputDefense03Error")
