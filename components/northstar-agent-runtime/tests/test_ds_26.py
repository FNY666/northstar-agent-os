"""DS tests: Cartesian Tree (ds_26)."""
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


m = _load("ds_26")


def test_root_is_min():
    root = m.cartesian_tree([9, 3, 7, 1, 8])
    assert root.val == 1


def test_inorder_is_original_order():
    arr = [4, 1, 5, 2, 3]
    root = m.cartesian_tree(arr)
    assert m.inorder_idx(root) == [0, 1, 2, 3, 4]


def test_heap_property():
    root = m.cartesian_tree([6, 2, 9, 4, 7, 1])
    assert m.check_heap(root) is True


def test_empty():
    assert m.cartesian_tree([]) is None
