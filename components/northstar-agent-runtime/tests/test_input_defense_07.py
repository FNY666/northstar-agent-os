"""Input defense 07 tests."""
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


mod = _load("input_defense_07")


def test_decode_once():
    assert mod.decode_once("&lt;b&gt;") == "<b>"
    assert mod.decode_once("&#x3C;div&#x3E;") == "<div>"
    assert mod.decode_once("no entities") == "no entities"


def test_is_double_encoded():
    assert mod.is_double_encoded("&amp;lt;") is True
    assert mod.is_double_encoded("&#38;#60;") is True
    assert mod.is_double_encoded("&lt;") is False
    assert mod.is_double_encoded("plain") is False


def test_check_double_encoded_is_suspicious():
    sus, dec = mod.check("&amp;lt;script&amp;gt;")
    assert sus is True
    assert dec == "&lt;script&gt;"


def test_check_single_encoded_marker_is_suspicious():
    sus, dec = mod.check("&#60;SCRIPT&#62;alert(1)")
    assert sus is True
    assert dec == "<SCRIPT>alert(1)"


def test_check_clean():
    sus, dec = mod.check("Tom &amp; Jerry")
    assert sus is False
    assert dec == "Tom & Jerry"


def test_non_str_raises():
    for fn in (mod.decode_once, mod.is_double_encoded, mod.check):
        try:
            fn(123)
        except mod.InputDefense07Error:
            pass
        else:
            raise AssertionError(f"{fn.__name__} must raise on non-str")
