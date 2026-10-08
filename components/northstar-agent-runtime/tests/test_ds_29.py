"""DS tests: Sparse Table (ds_29)."""
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


m = _load("ds_29")


def test_full_range():
    st = m.SparseTable([4, 1, 7, 3])
    assert st.query(0, 4) == 1


def test_sub_ranges():
    st = m.SparseTable([5, 2, 8, 1, 9])
    assert st.query(0, 3) == 2
    assert st.query(3, 5) == 1


def test_single():
    st = m.SparseTable([42])
    assert st.query(0, 1) == 42


def test_empty_range():
    st = m.SparseTable([1, 2])
    try:
        st.query(1, 1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
