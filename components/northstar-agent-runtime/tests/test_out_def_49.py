"""Out-def-49 SVG exfiltration tests."""

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


d49 = _load("out_def_49")


def test_script_tag_detected():
    found, _, evidence = d49.detect_svg_exfil("<svg><ScRiPt>alert(1)</ScRiPt></svg>")
    assert found is True
    assert evidence
    assert all(len(e["snippet"]) <= 80 for e in evidence)


def test_foreign_object_detected():
    found, _, _ = d49.detect_svg_exfil(
        '<svg><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"/></foreignObject></svg>'
    )
    assert found is True


def test_event_handler_detected():
    found, _, _ = d49.detect_svg_exfil('<svg><circle ONLOAD="evil()"/></svg>')
    assert found is True
    found, _, _ = d49.detect_svg_exfil('<svg><image onerror="evil()"/></svg>')
    assert found is True


def test_external_hrefs_detected():
    found, _, _ = d49.detect_svg_exfil(
        '<svg><a xlink:href="https://evil.example/x"><text>hi</text></a></svg>'
    )
    assert found is True
    found, _, _ = d49.detect_svg_exfil(
        '<svg><image href="data:image/png;base64,AAAA"/></svg>'
    )
    assert found is True


def test_embedded_tags_detected():
    for tag in ("iframe", "embed", "object"):
        found, _, _ = d49.detect_svg_exfil(f"<svg><{tag} src='x'/></svg>")
        assert found is True, tag


def test_clean_svg_passes():
    found, reason, evidence = d49.detect_svg_exfil(
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<circle cx="5" cy="5" r="4" fill="red"/></svg>'
    )
    assert found is False, reason
    assert evidence == []


def test_fail_closed_on_bad_input():
    try:
        d49.detect_svg_exfil(123)
    except d49.OutDef49Error:
        pass
    else:
        raise AssertionError("expected OutDef49Error")


def test_stdlib_only():
    assert d49.stdlib_only() is True


def test_version_pin():
    assert d49.OUT_DEF_49_VERSION == "out-def-49.v1"
    assert d49.SCHEMA_PIN == "northstar.out-def-49.v1"
