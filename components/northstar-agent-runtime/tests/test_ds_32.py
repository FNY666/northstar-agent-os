"""DS tests: Union-Find (ds_32)."""
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


m = _load("ds_32")


def test_union_connected():
    uf = m.UnionFind(4)
    uf.union(0, 1)
    assert uf.connected(0, 1) is True
    assert uf.connected(0, 2) is False


def test_transitive():
    uf = m.UnionFind(4)
    uf.union(0, 1); uf.union(1, 2)
    assert uf.connected(0, 2) is True


def test_redundant_union():
    uf = m.UnionFind(3)
    uf.union(0, 1)
    assert uf.union(0, 1) is False


def test_bad_index():
    uf = m.UnionFind(2)
    try:
        uf.find(5)
    except IndexError:
        pass
    else:
        raise AssertionError("expected IndexError")
