"""Input defense 04 tests."""
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


mod = _load("input_defense_04")


def test_valid_utf8_decodes():
    assert mod.normalize_bytes(b"hello") == "hello"
    assert mod.normalize_bytes("héllo→世界".encode("utf-8")) == "héllo→世界"
    assert mod.normalize_bytes(b"") == ""


def test_leading_bom_stripped():
    assert mod.normalize_bytes(b"\xef\xbb\xbfhello") == "hello"
    assert mod.normalize_text("\ufeffhello") == "hello"
    # Non-leading BOM preserved.
    assert mod.normalize_bytes("a\ufeffb".encode("utf-8")) == "a\ufeffb"


def test_invalid_utf8_raises():
    for bad in [b"\xff", b"\xfe", b"abc\x80\x81", b"\xed\xa0\x80"]:
        try:
            mod.normalize_bytes(bad)
        except mod.InputDefense04Error:
            continue
        raise AssertionError(f"expected InputDefense04Error for {bad!r}")


def test_is_valid_utf8():
    assert mod.is_valid_utf8(b"hello") is True
    assert mod.is_valid_utf8(b"") is True
    assert mod.is_valid_utf8(b"\xff") is False
    assert mod.is_valid_utf8(b"\xef\xbb\xbfbom") is True


def test_non_bytes_raises():
    try:
        mod.normalize_bytes("not bytes")
    except mod.InputDefense04Error:
        return
    raise AssertionError("expected InputDefense04Error")


def test_non_str_normalize_text_raises():
    try:
        mod.normalize_text(b"nope")
    except mod.InputDefense04Error:
        return
    raise AssertionError("expected InputDefense04Error")
