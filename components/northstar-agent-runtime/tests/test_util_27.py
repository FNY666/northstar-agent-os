"""util_27 tests."""

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


m = _load("util_27")

import dataclasses


@dataclasses.dataclass
class _P:
    x: int
    y: str = "a"


def test_to_dict_safe():
    assert m.to_dict_safe(_P(1)) == {"x": 1, "y": "a"}


def test_update():
    p = _P(1)
    q = m.update(p, y="b")
    assert q.y == "b" and p.y == "a"


def test_field_names():
    assert m.field_names(_P(1)) == ["x", "y"]


def test_not_dataclass():
    import pytest
    with pytest.raises(m.DataclassError):
        m.to_dict_safe(42)
    assert m.is_dataclass_instance(_P(1)) is True
    assert m.is_dataclass_instance(_P) is False


def test_stdlib_only():
    assert m.stdlib_only() is True
