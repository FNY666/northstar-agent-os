"""Audio exfiltration detection (mock) tests."""

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


m = _load("exfil_14")

def test_benign():
    ok, _ = m.detect_audio_exfil([{"api": "getUserMedia:audio", "consented": True}])
    assert ok is False


def test_no_consent():
    ok, reason = m.detect_audio_exfil([{"api": "MediaRecorder:audio", "consented": False}])
    assert ok is True
    assert "without consent" in reason


def test_unrelated_api():
    ok, _ = m.detect_audio_exfil([{"api": "fetch", "consented": False}])
    assert ok is False


def test_bad_input():
    import pytest
    with pytest.raises(m.Exfil14Error):
        m.detect_audio_exfil({})


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.EXFIL_14_VERSION == "exfil-14.v1"
