"""Tests for proto_04 (XML)."""

import importlib.util
import sys
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


m = _load("proto_04")

def test_root_tag():
    assert m.root_tag("<root><x/></root>") == "root"


def test_to_dict():
    d = m.xml_to_dict(m.parse_xml('<a k="v"><b>t</b></a>'))
    assert d["tag"] == "a" and d["attrib"] == {"k": "v"}
    assert d["children"][0] == {"tag": "b", "attrib": {}, "text": "t"}


def test_mismatched_rejected():
    with pytest.raises(m.Proto04Error):
        m.parse_xml("<a><b></a>")


def test_validate():
    ok, _ = m.validate_xml("<a/>")
    assert ok is True
    ok, _ = m.validate_xml("nope")
    assert ok is False


def test_stdlib_only():
    assert m.stdlib_only() is True

