"""Data exfiltration via formatting tests."""

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


d34 = _load("out_def_34")


def test_trailing_whitespace_flagged():
    found, reason, evidence = d34.detect_format_exfil("line one  \nline two\t\nthree")
    assert found is True
    assert "trailing-whitespace" in reason
    assert len([e for e in evidence if e["kind"] == "trailing-whitespace"]) == 2


def test_inconsistent_indentation_flagged():
    found, reason, evidence = d34.detect_format_exfil("  a\n\tb\n  c\n\td\n  e")
    assert found is True
    assert "inconsistent-indentation" in reason


def test_whitespace_blank_lines_flagged():
    found, reason, evidence = d34.detect_format_exfil("a\n   \n  \nb")
    assert found is True
    assert "whitespace-blank-lines" in reason


def test_clean_text_passes():
    found, _, _ = d34.detect_format_exfil("normal\n  indented\ntext")
    assert found is False


def test_cleaner_removes_channel():
    cleaned = d34.clean_format_exfil("a  \nb\t")
    assert cleaned == "a\nb"
    found, _, _ = d34.detect_format_exfil(cleaned)
    assert found is False


def test_non_str_fail_closed():
    try:
        d34.detect_format_exfil(b"bytes")
    except d34.OutDef34Error:
        pass
    else:
        raise AssertionError("non-str input should fail closed")


def test_stdlib_only():
    assert d34.stdlib_only() is True


def test_version_pin():
    assert d34.OUT_DEF_34_VERSION == "out-def-34.v1"
    assert d34.SCHEMA_PIN == "northstar.out-def-34.v1"
