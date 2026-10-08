"""Input defense 15 tests."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
mod = _load("input_defense_15")


def test_remove_rlo_spoof():
    spoof = "evil‮exe"  # RLO: the "evil.exe" spoof vector
    cleaned, removed = mod.remove(spoof)
    assert cleaned == "evilexe"
    assert removed == 1


def test_remove_all_nine_controls():
    payload = "‪x‫y‬z‭w‮v⁦u⁧t⁨s⁩q"
    cleaned, removed = mod.remove(payload)
    assert cleaned == "xyzwvutsq"
    assert removed == 9


def test_has_bidi():
    assert mod.has_bidi("a‮b") is True
    assert mod.has_bidi("⁨isolated⁩") is True
    assert mod.has_bidi("clean") is False
    assert mod.has_bidi("") is False


def test_clean_input_unchanged():
    assert mod.remove("clean") == ("clean", 0)


def test_non_str_raises():
    for bad in (None, 123, b"clean", ["clean"]):
        try:
            mod.remove(bad)
        except mod.InputDefense15Error:
            pass
        else:
            raise AssertionError("remove(%r) did not raise" % (bad,))
        try:
            mod.has_bidi(bad)
        except mod.InputDefense15Error:
            pass
        else:
            raise AssertionError("has_bidi(%r) did not raise" % (bad,))


def test_stdlib_only():
    assert mod.stdlib_only() is True
