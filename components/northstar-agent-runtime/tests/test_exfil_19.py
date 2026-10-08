"""URL parameter smuggling detection tests."""

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


m = _load("exfil_19")

def test_benign():
    ok, _ = m.detect_url_param_smuggling("https://x.com/?q=hi")
    assert ok is False


def test_duplicate():
    ok, reason = m.detect_url_param_smuggling("https://x.com/?a=1&a=2")
    assert ok is True
    assert "duplicate" in reason


def test_sensitive():
    ok, _ = m.detect_url_param_smuggling("https://x.com/?id=123-45-6789")
    assert ok is True


def test_double_encoded():
    ok, _ = m.detect_url_param_smuggling("https://x.com/?q=%2520")
    assert ok is True


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.EXFIL_19_VERSION == "exfil-19.v1"
