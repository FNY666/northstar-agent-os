"""Document property stripping defense tests (D-OUT-040)."""

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


m = _load("out_def_40")


def test_sensitive_props_threat():
    threat, reason = m.detect_doc_props(
        {"title": "Q3", "author": "mallory", "company": "Evil Corp"}
    )
    assert threat is True
    assert "author" in reason


def test_empty_sensitive_value_clean():
    threat, _ = m.detect_doc_props({"author": "   ", "title": "Q3"})
    assert threat is False


def test_no_sensitive_props_clean():
    threat, _ = m.detect_doc_props({"title": "Q3", "pages": 10})
    assert threat is False


def test_strip_doc_props():
    cleaned, removed = m.strip_doc_props(
        {"title": "Q3", "author": "mallory", "subject": "leak"},
        keep={"title"},
    )
    assert cleaned == {"title": "Q3"}
    assert sorted(removed) == ["author", "subject"]


def test_strip_default_removes_all():
    cleaned, removed = m.strip_doc_props({"title": "Q3"})
    assert cleaned == {}
    assert removed == ["title"]


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.OUT_DEF_40_VERSION == "out-def-40.v1"
    assert m.SCHEMA_PIN == "northstar.out-def-40.v1"
