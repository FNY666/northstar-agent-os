"""Input defense 08 tests."""
import importlib.util
import sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


mod = _load("input_defense_08")


def test_decode_all_multi_round():
    dec, rounds = mod.decode_all("%252e%252e%252fetc/passwd")
    assert dec == "../etc/passwd"
    assert rounds == 2


def test_decode_all_stable():
    dec, rounds = mod.decode_all("hello world")
    assert dec == "hello world"
    assert rounds == 0


def test_check_multi_encoded_suspicious():
    sus, dec, rounds = mod.check("%252e%252e%252fetc%252fpasswd")
    assert sus is True
    assert dec == "../etc/passwd"
    assert rounds == 2


def test_check_marker_suspicious_single_round():
    sus, dec, rounds = mod.check("%3Cscript%3Ealert(1)")
    assert sus is True
    assert dec == "<script>alert(1)"
    assert rounds == 1


def test_check_clean_single_decode():
    sus, dec, rounds = mod.check("hello%20world")
    assert sus is False
    assert dec == "hello world"
    assert rounds == 1


def test_non_str_raises():
    for fn in (mod.decode_all, mod.check):
        try:
            fn(None)
        except mod.InputDefense08Error:
            pass
        else:
            raise AssertionError(f"{fn.__name__} must raise on non-str")
