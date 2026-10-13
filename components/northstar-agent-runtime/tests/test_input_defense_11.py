"""Input defense 11 tests."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
mod = _load("input_defense_11")


def test_normalize_cyrillic_spoof():
    assert mod.normalize("раураl") == "paypal"


def test_normalize_greek():
    assert mod.normalize("αεор") == "aeop"


def test_normalize_fullwidth_ranges():
    assert mod.normalize_fullwidth("ＡＢＣａｂｃ０１２") == "ABCabc012"
    assert mod.normalize("Ｈｅｌｌｏ") == "Hello"


def test_normalize_plain_ascii_fixed_point():
    assert mod.normalize("paypal") == "paypal"
    assert mod.normalize("") == ""


def test_normalize_non_str_raises():
    for bad in (None, 123, b"paypal", ["paypal"]):
        try:
            mod.normalize(bad)
        except mod.InputDefense11Error:
            pass
        else:
            raise AssertionError("normalize(%r) did not raise" % (bad,))
        try:
            mod.normalize_fullwidth(bad)
        except mod.InputDefense11Error:
            pass
        else:
            raise AssertionError("normalize_fullwidth(%r) did not raise" % (bad,))


def test_stdlib_only():
    assert mod.stdlib_only() is True
