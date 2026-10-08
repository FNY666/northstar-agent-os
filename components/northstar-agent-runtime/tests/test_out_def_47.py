"""Out-def-47 CSS exfiltration tests."""

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


d47 = _load("out_def_47")


def test_data_url_detected():
    found, _, evidence = d47.detect_css_exfil(
        ".x { background: url(data:image/png;base64,iVBORw0KGgo=); }"
    )
    assert found is True
    assert evidence
    assert all(len(e["snippet"]) <= 80 for e in evidence)


def test_external_url_and_import_detected():
    found, _, _ = d47.detect_css_exfil(
        '.x { background: url("https://evil.example/a.png"); }'
    )
    assert found is True
    found, _, _ = d47.detect_css_exfil('@import url("http://evil.example/a.css");')
    assert found is True


def test_expression_and_behavior_detected():
    found, _, _ = d47.detect_css_exfil(".x { width: expression(alert(1)); }")
    assert found is True
    found, _, _ = d47.detect_css_exfil(".x { behavior: url(evil.htc); }")
    assert found is True
    found, _, _ = d47.detect_css_exfil(".x { -moz-binding: url(evil.xml#x); }")
    assert found is True


def test_long_content_string_detected():
    found, _, _ = d47.detect_css_exfil('.x::after { content: "' + "Q" * 70 + '"; }')
    assert found is True


def test_clean_css_passes():
    found, reason, evidence = d47.detect_css_exfil(
        'body { color: red; font-size: 14px; } .x::after { content: "ok"; }'
    )
    assert found is False, reason
    assert evidence == []


def test_fail_closed_on_bad_input():
    try:
        d47.detect_css_exfil(b"not str")
    except d47.OutDef47Error:
        pass
    else:
        raise AssertionError("expected OutDef47Error")


def test_stdlib_only():
    assert d47.stdlib_only() is True


def test_version_pin():
    assert d47.OUT_DEF_47_VERSION == "out-def-47.v1"
    assert d47.SCHEMA_PIN == "northstar.out-def-47.v1"
