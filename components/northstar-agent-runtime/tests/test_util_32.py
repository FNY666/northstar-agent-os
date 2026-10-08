"""util_32 tests."""

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


m = _load("util_32")

def test_uuid4():
    import uuid
    assert uuid.UUID(m.uuid4_str()).version == 4


def test_uuid5_deterministic():
    import uuid
    a = m.uuid5_str(uuid.NAMESPACE_DNS, "example.com")
    assert m.uuid5_str(uuid.NAMESPACE_DNS, "example.com") == a
    assert uuid.UUID(a).version == 5


def test_parse_and_check():
    import uuid
    u = m.uuid4_str()
    assert m.parse_uuid(u) == uuid.UUID(u)
    assert m.is_uuid(u) is True
    assert m.is_uuid("nope") is False


def test_parse_bad():
    import pytest
    with pytest.raises(m.UuidError):
        m.parse_uuid("nope")


def test_stdlib_only():
    assert m.stdlib_only() is True
