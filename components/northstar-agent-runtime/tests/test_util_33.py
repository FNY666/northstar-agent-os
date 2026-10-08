"""util_33 tests."""

import importlib.util
import sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


m = _load("util_33")

def test_hex_to_rgb():
    assert m.hex_to_rgb("#ff0000") == (255, 0, 0)
    assert m.hex_to_rgb("0f0") == (0, 255, 0)


def test_rgb_to_hex():
    assert m.rgb_to_hex(255, 0, 0) == "#ff0000"
    assert m.hex_to_rgb(m.rgb_to_hex(1, 2, 3)) == (1, 2, 3)


def test_bad_color():
    import pytest
    with pytest.raises(m.ColorError):
        m.hex_to_rgb("zzz")
    with pytest.raises(m.ColorError):
        m.rgb_to_hex(300, 0, 0)


def test_ansi():
    s = m.ansi_fg(255, 0, 0) + "x" + m.ansi_reset()
    assert m.strip_ansi(s) == "x"


def test_stdlib_only():
    assert m.stdlib_only() is True
