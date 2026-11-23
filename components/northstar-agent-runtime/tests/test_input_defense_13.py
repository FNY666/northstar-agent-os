"""Input defense 13 tests."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
mod = _load("input_defense_13")


def test_script_mixing_spoof_is_suspicious():
    suspicious, scripts = mod.check("раураl")
    assert suspicious is True
    assert scripts == {"cyrillic", "latin"}


def test_single_script_is_clean():
    assert mod.check("paypal") == (False, {"latin"})
    assert mod.check("αβγ") == (False, {"greek"})
    assert mod.check("中文字") == (False, {"cjk"})


def test_max_scripts_parameter():
    suspicious, scripts = mod.check("раураl", max_scripts=2)
    assert suspicious is False
    assert scripts == {"cyrillic", "latin"}


def test_neutral_chars_ignored():
    assert mod.scripts_in("paypal 123!") == {"latin"}
    assert mod.scripts_in("") == set()


def test_script_of_mapping():
    assert mod.script_of("a") == "latin"
    assert mod.script_of("р") == "cyrillic"
    assert mod.script_of("α") == "greek"
    assert mod.script_of("中") == "cjk"
    assert mod.script_of("ع") == "arabic"
    assert mod.script_of("3") == "neutral"
    assert mod.script_of(" ") == "neutral"


def test_non_str_raises():
    for bad in (None, 123, b"paypal", ["paypal"]):
        try:
            mod.check(bad)
        except mod.InputDefense13Error:
            pass
        else:
            raise AssertionError("check(%r) did not raise" % (bad,))
        try:
            mod.scripts_in(bad)
        except mod.InputDefense13Error:
            pass
        else:
            raise AssertionError("scripts_in(%r) did not raise" % (bad,))


def test_stdlib_only():
    assert mod.stdlib_only() is True
