"""Tests for dx_08 scaffolding."""
import importlib.util, sys
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent

def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m

dx = _load("dx_08")


def test_tree_contents():
    tree = dx.scaffold(dx.ProjectSpec(name="myapp", modules=["gates"]))
    assert "myapp/__init__.py" in tree
    assert "myapp/__main__.py" in tree
    assert "myapp/core.py" in tree
    assert "myapp/gates.py" in tree
    assert "tests/test_gates.py" in tree
    assert "README.md" in tree
    assert "{{" not in tree["myapp/__main__.py"]


def test_no_tests_no_readme():
    tree = dx.scaffold(dx.ProjectSpec(name="app", modules=[], with_tests=False, with_readme=False))
    assert "README.md" not in tree
    assert "tests/__init__.py" not in tree
    assert "app/core.py" in tree


def test_bad_project_name_raises():
    with pytest.raises(dx.ScaffoldError):
        dx.scaffold(dx.ProjectSpec(name="bad-name", modules=[]))


def test_bad_module_name_raises():
    with pytest.raises(dx.ScaffoldError):
        dx.scaffold(dx.ProjectSpec(name="ok", modules=["bad mod"]))


def test_duplicate_modules_raise():
    with pytest.raises(dx.ScaffoldError):
        dx.scaffold(dx.ProjectSpec(name="ok", modules=["a", "a"]))


def test_stdlib_only():
    assert dx.stdlib_only() is True


def test_version_pin():
    assert dx.DX08_SCAFFOLD_VERSION == "dx-scaffold.v1"
