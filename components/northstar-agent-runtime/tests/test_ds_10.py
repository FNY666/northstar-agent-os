"""DS tests: Binary Tree (ds_10)."""
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


m = _load("ds_10")


def _tree():
    return m.TreeNode(1, m.TreeNode(2, m.TreeNode(4), m.TreeNode(5)), m.TreeNode(3))


def test_inorder():
    assert m.inorder(_tree()) == [4, 2, 5, 1, 3]


def test_preorder():
    assert m.preorder(_tree()) == [1, 2, 4, 5, 3]


def test_postorder():
    assert m.postorder(_tree()) == [4, 5, 2, 3, 1]


def test_height():
    assert m.height(_tree()) == 3
    assert m.height(None) == 0
