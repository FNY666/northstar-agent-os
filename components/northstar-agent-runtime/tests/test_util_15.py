"""util_15 tests."""

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


m = _load("util_15")

def test_event_json():
    import json
    rec = json.loads(m.event_json("info", "started", run_id=1))
    assert rec["event"] == "started"
    assert rec["level"] == "INFO"
    assert rec["run_id"] == 1
    assert "ts" in rec


def test_redact():
    assert m.redact({"pw": "x", "u": "y"}, ["pw"]) == {"pw": "***", "u": "y"}


def test_make_logger():
    logger = m.make_logger("util15-test")
    assert logger.name == "util15-test"


def test_stdlib_only():
    assert m.stdlib_only() is True
