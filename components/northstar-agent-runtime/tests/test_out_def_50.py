"""Out-def-50 MathML exfiltration tests."""

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


d50 = _load("out_def_50")


def test_annotation_html_encoding_detected():
    found, _, evidence = d50.detect_mathml_exfil(
        '<math><annotation encoding="text/html"><img src=x onerror=y></annotation></math>'
    )
    assert found is True
    assert evidence
    assert all(len(e["snippet"]) <= 80 for e in evidence)


def test_annotation_application_encoding_detected():
    found, _, _ = d50.detect_mathml_exfil(
        '<math><annotation ENCODING="Application/octet-stream">xx</annotation></math>'
    )
    assert found is True


def test_annotation_xml_non_mathml_detected():
    found, _, _ = d50.detect_mathml_exfil(
        '<math><annotation-xml encoding="image/svg+xml"><svg/></annotation-xml></math>'
    )
    assert found is True


def test_href_mglyph_maction_detected():
    found, _, _ = d50.detect_mathml_exfil(
        '<math><mtext href="https://evil.example/x">click</mtext></math>'
    )
    assert found is True
    found, _, _ = d50.detect_mathml_exfil(
        '<math><mglyph src="https://evil.example/g.png" alt="g"/></math>'
    )
    assert found is True
    found, _, _ = d50.detect_mathml_exfil(
        '<math><maction actiontype="exfiltrate"><mtext>a</mtext></maction></math>'
    )
    assert found is True


def test_clean_mathml_passes():
    found, reason, evidence = d50.detect_mathml_exfil(
        '<math><mi>x</mi><mo>+</mo><mn>1</mn>'
        '<annotation encoding="text">x is a variable</annotation>'
        '<maction actiontype="toggle"><mtext>a</mtext></maction></math>'
    )
    assert found is False, reason
    assert evidence == []


def test_fail_closed_on_bad_input():
    try:
        d50.detect_mathml_exfil(["not str"])
    except d50.OutDef50Error:
        pass
    else:
        raise AssertionError("expected OutDef50Error")


def test_stdlib_only():
    assert d50.stdlib_only() is True


def test_version_pin():
    assert d50.OUT_DEF_50_VERSION == "out-def-50.v1"
    assert d50.SCHEMA_PIN == "northstar.out-def-50.v1"
