"""DS tests: Suffix Trie (ds_16)."""
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


m = _load("ds_16")


def test_contains():
    st = m.SuffixTrie("banana")
    assert st.contains("ban") is True
    assert st.contains("ana") is True


def test_missing():
    st = m.SuffixTrie("banana")
    assert st.contains("nab") is False


def test_rebuild():
    st = m.SuffixTrie()
    st.build("abc")
    assert st.contains("bc") is True
    assert st.suffix_count() == 3
