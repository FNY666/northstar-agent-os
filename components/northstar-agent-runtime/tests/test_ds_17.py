"""DS tests: Hash Table (ds_17)."""
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


m = _load("ds_17")


def test_put_get():
    h = m.HashTable()
    h.put("k", "v")
    assert h.get("k") == "v"


def test_overwrite():
    h = m.HashTable()
    h.put("k", 1); h.put("k", 2)
    assert h.get("k") == 2
    assert len(h) == 1


def test_missing_key():
    h = m.HashTable()
    try:
        h.get("nope")
    except KeyError:
        pass
    else:
        raise AssertionError("expected KeyError")


def test_delete():
    h = m.HashTable()
    h.put(1, "a")
    assert h.delete(1) is True
    assert h.delete(1) is False
