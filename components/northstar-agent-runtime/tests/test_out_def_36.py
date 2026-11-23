"""Homoglyph exfiltration defense tests (D-OUT-036)."""

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


m = _load("out_def_36")


def test_mixed_script_threat():
    # Cyrillic 'а' (U+0430) smuggled into a Latin token.
    threat, reason = m.detect_mixed_script("pаssword")
    assert threat is True
    assert "mixed-script" in reason


def test_pure_latin_clean():
    threat, _ = m.detect_mixed_script("password")
    assert threat is False


def test_scan_text_finds_tokens():
    threat, _, bad = m.scan_text("all clean pаssword here")
    assert threat is True
    assert bad == ["pаssword"]


def test_scan_text_clean():
    threat, _, bad = m.scan_text("nothing to see here")
    assert threat is False
    assert bad == []


def test_normalize_confusables():
    assert m.normalize_confusables("hеllo wοrld") == "hello world"


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.OUT_DEF_36_VERSION == "out-def-36.v1"
    assert m.SCHEMA_PIN == "northstar.out-def-36.v1"
