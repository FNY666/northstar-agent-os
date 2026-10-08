"""DS tests: Bloom Filter (ds_22)."""
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


m = _load("ds_22")


def test_no_false_negatives():
    bf = m.BloomFilter()
    for w in ("a", "b", "c"):
        bf.add(w)
    for w in ("a", "b", "c"):
        assert bf.might_contain(w) is True


def test_absent():
    bf = m.BloomFilter()
    assert bf.might_contain("never-added") is False


def test_capacity_validation():
    try:
        m.BloomFilter(capacity=0)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
