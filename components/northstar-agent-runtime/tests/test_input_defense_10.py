"""Input defense 10 tests."""
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


mod = _load("input_defense_10")

SCRIPT_HEX = "<script>alert(1)</script>".encode("utf-8").hex()
SELECT_HEX = "SELECT * FROM users".encode("utf-8").hex()
BENIGN_HEX = "deadbeef" * 8


def test_find_candidates():
    assert mod.find_candidates("see " + SCRIPT_HEX + " end") == [SCRIPT_HEX]
    assert mod.find_candidates("deadbeef") == []  # too short (< 32)
    assert mod.find_candidates("plain text") == []


def test_decode_hex():
    raw = mod.decode_hex(SCRIPT_HEX)
    assert raw == b"<script>alert(1)</script>"
    assert mod.decode_hex("zz") is None
    assert mod.decode_hex("abc") is None  # odd length


def test_check_script_suspicious():
    sus, hits = mod.check("see " + SCRIPT_HEX + " end")
    assert sus is True
    assert hits == ["<script>alert(1)</script>"]


def test_check_select_suspicious():
    sus, hits = mod.check("q=" + SELECT_HEX)
    assert sus is True
    assert hits == ["SELECT * FROM users"]


def test_check_benign_hex_not_suspicious():
    sus, hits = mod.check("blob " + BENIGN_HEX)
    assert sus is False
    assert hits == []


def test_non_str_raises():
    for fn in (mod.find_candidates, mod.decode_hex, mod.check):
        try:
            fn(object())
        except mod.InputDefense10Error:
            pass
        else:
            raise AssertionError(f"{fn.__name__} must raise on non-str")
