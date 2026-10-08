"""Metadata exfiltration defense tests (D-OUT-038)."""

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


m = _load("out_def_38")


def test_disallowed_key_flagged():
    threat, _, ev = m.detect_meta_exfil({"title": "t", "author": "mallory"})
    assert threat is True
    assert any("author" in e for e in ev)


def test_email_in_value_flagged():
    threat, _, ev = m.detect_meta_exfil({"title": "hi bob@example.com"})
    assert threat is True
    assert any("email" in e for e in ev)


def test_path_and_token_flagged():
    threat, _, _ = m.detect_meta_exfil({"format": "pdf /etc/passwd"})
    assert threat is True
    threat, _, _ = m.detect_meta_exfil({"title": "k=sk-abcdefghijklmnopqrst"})
    assert threat is True


def test_clean_meta_passes():
    threat, _, ev = m.detect_meta_exfil({"title": "Report", "format": "pdf"})
    assert threat is False
    assert ev == []


def test_strip_meta():
    cleaned = m.strip_meta(
        {"title": "x" * 500, "format": "pdf", "author": "mallory"}
    )
    assert set(cleaned) == {"title", "format"}
    assert len(cleaned["title"]) == 200
    assert cleaned["format"] == "pdf"


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.OUT_DEF_38_VERSION == "out-def-38.v1"
    assert m.SCHEMA_PIN == "northstar.out-def-38.v1"
