"""Out-def-46 font exfiltration tests."""

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


d46 = _load("out_def_46")


def test_base64_token_detected():
    token = "QUJD" * 16
    found, _, evidence = d46.detect_font_exfil(
        [{"name_id": 1, "string": "MyFont " + token}]
    )
    assert found is True
    assert evidence
    assert any("base64" in f for e in evidence for f in e["flags"])


def test_control_chars_detected():
    found, _, evidence = d46.detect_font_exfil(
        [{"name_id": 2, "string": "a\x07b"}]
    )
    assert found is True
    assert evidence


def test_unexpected_name_id_long_string_detected():
    found, _, evidence = d46.detect_font_exfil(
        [{"name_id": 42, "string": "y" * 100}]
    )
    assert found is True
    assert evidence


def test_clean_name_table_passes():
    found, reason, evidence = d46.detect_font_exfil(
        [
            {"name_id": 1, "string": "My Font"},
            {"name_id": 3, "string": "Copyright 2026 Example Foundry. " * 8},
            {"name_id": 99, "string": "short"},
        ]
    )
    assert found is False, reason
    assert evidence == []


def test_fail_closed_on_bad_input():
    try:
        d46.detect_font_exfil("not a list")
    except d46.OutDef46Error:
        pass
    else:
        raise AssertionError("expected OutDef46Error")


def test_stdlib_only():
    assert d46.stdlib_only() is True


def test_version_pin():
    assert d46.OUT_DEF_46_VERSION == "out-def-46.v1"
    assert d46.SCHEMA_PIN == "northstar.out-def-46.v1"
