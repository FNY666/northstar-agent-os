"""DS tests: Segment Tree (ds_27)."""
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


m = _load("ds_27")


def test_full_range():
    st = m.SegmentTree([1, 2, 3, 4])
    assert st.query(0, 4) == 10


def test_partial_range():
    st = m.SegmentTree([1, 2, 3, 4, 5])
    assert st.query(1, 4) == 9
    assert st.query(0, 1) == 1


def test_update():
    st = m.SegmentTree([1, 2, 3])
    st.update(1, 20)
    assert st.query(0, 3) == 24


def test_bad_range():
    st = m.SegmentTree([1, 2])
    try:
        st.query(2, 1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
