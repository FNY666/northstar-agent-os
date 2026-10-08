"""util_20 tests."""

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


m = _load("util_20")

def test_mock_clock():
    c = m.MockClock(start=10.0)
    c.sleep(5)
    assert c.now() == 15.0
    c.advance(2.5)
    assert c.now() == 17.5


def test_capture_stdout():
    with m.capture_stdout() as buf:
        print("hello")
    assert buf.getvalue() == "hello\n"


def test_assert_raises_msg():
    e = m.assert_raises_msg(ValueError, lambda: int("x"), "invalid literal")
    assert isinstance(e, ValueError)


def test_temp_cwd(tmp_path):
    import os
    with m.temp_cwd(str(tmp_path)):
        assert os.getcwd() == str(tmp_path)


def test_stdlib_only():
    assert m.stdlib_only() is True
