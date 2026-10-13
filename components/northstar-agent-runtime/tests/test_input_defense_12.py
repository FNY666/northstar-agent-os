"""Input defense 12 tests."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
mod = _load("input_defense_12")


def test_find_confusables_positions():
    hits = mod.find_confusables("раураl")
    assert hits == [("р", 0), ("а", 1), ("у", 2), ("р", 3), ("а", 4)]


def test_check_spoof_is_suspicious():
    suspicious, hits = mod.check("раураl")
    assert suspicious is True
    assert len(hits) == 5


def test_check_clean_is_not_suspicious():
    assert mod.find_confusables("paypal") == []
    assert mod.check("paypal") == (False, [])
    assert mod.check("") == (False, [])


def test_check_greek_confusables():
    suspicious, hits = mod.check("αεор")
    assert suspicious is True
    assert len(hits) == 4


def test_non_str_raises():
    for bad in (None, 123, b"paypal", ["paypal"]):
        try:
            mod.check(bad)
        except mod.InputDefense12Error:
            pass
        else:
            raise AssertionError("check(%r) did not raise" % (bad,))
        try:
            mod.find_confusables(bad)
        except mod.InputDefense12Error:
            pass
        else:
            raise AssertionError("find_confusables(%r) did not raise" % (bad,))


def test_stdlib_only():
    assert mod.stdlib_only() is True
