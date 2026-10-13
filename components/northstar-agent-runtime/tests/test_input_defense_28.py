"""Tests for input_defense_28."""
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


mod = _load("input_defense_28")

SCHEMA = {"required": ["cmd"],
          "properties": {"cmd": {"type": "str", "enum": ["read", "list"]},
                         "n": {"type": "int"}},
          "no_extra": True}


def test_valid():
    assert mod.validate({"cmd": "read", "n": 1}, SCHEMA) is True


def test_missing():
    try:
        mod.validate({"n": 1}, SCHEMA)
    except mod.InputDefenseError:
        return
    raise AssertionError("should raise")


def test_bad_enum():
    try:
        mod.validate({"cmd": "delete"}, SCHEMA)
    except mod.InputDefenseError:
        return
    raise AssertionError("should raise")


def test_extra_field():
    try:
        mod.validate({"cmd": "read", "evil": 1}, SCHEMA)
    except mod.InputDefenseError:
        return
    raise AssertionError("should raise")


def test_bool_not_int():
    try:
        mod.validate({"cmd": "read", "n": True}, SCHEMA)
    except mod.InputDefenseError:
        return
    raise AssertionError("should raise")


def test_stdlib_only():
    assert mod.stdlib_only() is True

