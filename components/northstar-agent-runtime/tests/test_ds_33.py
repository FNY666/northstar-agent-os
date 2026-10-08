"""DS tests: Link-Cut Tree (ds_33)."""
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


m = _load("ds_33")


def test_link_connected():
    t = m.LinkCutTree()
    t.link("a", "b")
    assert t.connected("a", "b") is True


def test_cut():
    t = m.LinkCutTree()
    t.link(1, 2); t.link(2, 3)
    t.cut(1, 2)
    assert t.connected(1, 3) is False
    assert t.connected(2, 3) is True


def test_cycle_rejected():
    t = m.LinkCutTree()
    t.link(1, 2)
    try:
        t.link(1, 2)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_self_connected():
    t = m.LinkCutTree()
    assert t.connected("x", "x") is True
