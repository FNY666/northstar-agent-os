"""White-text exfiltration defense tests (D-OUT-037)."""

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


m = _load("out_def_37")


def test_white_text_threat():
    threat, _, ev = m.detect_white_text(
        '<span style="color:#fff">secret payload</span>'
    )
    assert threat is True
    assert any("secret payload" in e for e in ev)


def test_hidden_styles_detected():
    threat, _, _ = m.detect_white_text(
        "<div style='display:none'>x</div><p style='font-size:0'>y</p>"
    )
    assert threat is True
    threat, _, _ = m.detect_white_text(
        '<b style="visibility:hidden">v</b><i style="opacity:0">o</i>'
    )
    assert threat is True


def test_case_and_whitespace_tolerant():
    threat, _, _ = m.detect_white_text("<DIV STYLE=' COLOR : WHITE '>hidden</DIV>")
    assert threat is True


def test_hidden_style_no_text_clean():
    threat, _, ev = m.detect_white_text('<span style="display:none"></span>')
    assert threat is False
    assert ev == []


def test_visible_style_clean():
    threat, _, _ = m.detect_white_text('<p style="color:#000">hello</p>')
    assert threat is False


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.OUT_DEF_37_VERSION == "out-def-37.v1"
    assert m.SCHEMA_PIN == "northstar.out-def-37.v1"
