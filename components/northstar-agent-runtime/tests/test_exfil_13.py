"""Screenshot exfiltration detection (mock) tests."""

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


m = _load("exfil_13")

def test_benign():
    ok, _ = m.detect_screenshot_exfil(["fetch", "render"])
    assert ok is False


def test_canvas_readback():
    ok, reason = m.detect_screenshot_exfil(["canvas.toDataURL"])
    assert ok is True
    assert "canvas.toDataURL" in reason


def test_display_media():
    ok, _ = m.detect_screenshot_exfil(["getDisplayMedia"])
    assert ok is True


def test_bad_input():
    import pytest
    with pytest.raises(m.Exfil13Error):
        m.detect_screenshot_exfil(None)


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.EXFIL_13_VERSION == "exfil-13.v1"
