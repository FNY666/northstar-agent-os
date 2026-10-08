"""Tests for combo_15 (Hop-aware pipeline)."""

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


combo = _load("combo_15")


def _pipe():
    schema = combo.hv.HopSchema("h", frozenset({"q"}), frozenset({"q"}))
    return combo.HopAwarePipeline(schema)


def test_valid_hop():
    p = _pipe()
    s = p.process("t", {"q": "hi"})
    assert s["hop"]["q"] == "hi"


def test_strings_delimited():
    p = _pipe()
    s = p.process("t", {"q": "hi"})
    assert s["nonces"]["q"] in s["marked"]["q"]


def test_bad_hop_fails():
    p = _pipe()
    try:
        p.process("t", {"wrong": 1})
    except combo.ComboError:
        return
    raise AssertionError("expected ComboError")


def test_chain():
    p = _pipe()
    s1 = p.process("a", {"q": "1"})
    s2 = p.process("b", {"q": "2"})
    c = p.chain([s1, s2])
    assert {"a", "b"} <= set(c.deps)


def test_stdlib_only():
    assert combo.stdlib_only() is True
