"""Unicode exfiltration detection tests."""

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


d35 = _load("out_def_35")


def test_zero_width_detected():
    found, reason, evidence = d35.detect_unicode_exfil("hi\u200bthere")
    assert found is True
    assert evidence[0]["name"] == "ZERO WIDTH SPACE"
    assert evidence[0]["codepoint"] == "U+200B"


def test_bidi_override_detected():
    found, _, evidence = d35.detect_unicode_exfil("abc\u202edef")
    assert found is True
    assert any(e["name"] == "RIGHT-TO-LEFT OVERRIDE" for e in evidence)


def test_tag_char_detected():
    found, _, evidence = d35.detect_unicode_exfil("a\U000E0041b")
    assert found is True
    assert evidence[0]["codepoint"] == "U+E0041"


def test_soft_hyphen_detected():
    found, _, evidence = d35.detect_unicode_exfil("soft\u00adhyphen")
    assert found is True
    assert evidence[0]["name"] == "SOFT HYPHEN"


def test_clean_text_passes():
    found, _, _ = d35.detect_unicode_exfil("plain ascii text")
    assert found is False


def test_cleaner_removes_all():
    assert d35.clean_unicode_exfil("a\u200bb\u202ec\U000E0041") == "abc"


def test_non_str_fail_closed():
    try:
        d35.detect_unicode_exfil(b"bytes")
    except d35.OutDef35Error:
        pass
    else:
        raise AssertionError("non-str input should fail closed")


def test_stdlib_only():
    assert d35.stdlib_only() is True


def test_version_pin():
    assert d35.OUT_DEF_35_VERSION == "out-def-35.v1"
    assert d35.SCHEMA_PIN == "northstar.out-def-35.v1"
