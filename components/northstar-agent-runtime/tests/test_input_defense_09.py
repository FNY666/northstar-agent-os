"""Input defense 09 tests."""
import base64
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


mod = _load("input_defense_09")

EVIL = base64.b64encode(b"exec <http://evil.example.com/x.sh> -- download").decode("ascii")
BENIGN = base64.b64encode(
    b"the quick brown fox jumps over the lazy dog and then some"
).decode("ascii")
BINARY = base64.b64encode(bytes(range(256))).decode("ascii")


def test_find_candidates():
    assert mod.find_candidates("x " + EVIL + " y") == [EVIL]
    assert mod.find_candidates("aGVsbG8=") == []  # too short
    assert mod.find_candidates("nothing here") == []


def test_is_valid_b64():
    assert mod.is_valid_b64("aGVsbG8=") is True
    assert mod.is_valid_b64("!!!not b64!!!") is False
    assert mod.is_valid_b64("abc") is False


def test_check_suspicious_marker():
    sus, cands = mod.check("payload " + EVIL)
    assert sus is True
    assert cands == [EVIL]


def test_check_suspicious_binary():
    sus, cands = mod.check(BINARY)
    assert sus is True
    assert cands == [BINARY]


def test_check_benign_blob_not_suspicious():
    sus, cands = mod.check("log: " + BENIGN)
    assert sus is False
    assert cands == [BENIGN]


def test_non_str_raises():
    for fn in (mod.find_candidates, mod.is_valid_b64, mod.check):
        try:
            fn(123)
        except mod.InputDefense09Error:
            pass
        else:
            raise AssertionError(f"{fn.__name__} must raise on non-str")
