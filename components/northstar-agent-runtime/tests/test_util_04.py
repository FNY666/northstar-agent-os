"""util_04 tests."""

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


m = _load("util_04")

def test_token_length():
    assert len(m.secure_token(16)) == 32
    assert len(m.secure_token(8)) == 16


def test_random_int_range():
    for _ in range(20):
        assert 5 <= m.random_int(5, 10) <= 10


def test_choice_and_shuffle():
    assert m.secure_choice(["a"]) == "a"
    assert sorted(m.secure_shuffle([3, 1, 2])) == [1, 2, 3]


def test_uuid4():
    import uuid
    assert uuid.UUID(m.uuid4_str()).version == 4


def test_stdlib_only():
    assert m.stdlib_only() is True
