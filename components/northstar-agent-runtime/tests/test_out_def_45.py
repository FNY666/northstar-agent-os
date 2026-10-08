"""Archive metadata scrubber tests."""

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


m45 = _load("out_def_45")


def _local_header(filename, extra):
    fixed = b"PK\x03\x04" + b"\x00" * 22
    fixed += len(filename).to_bytes(2, "little") + len(extra).to_bytes(2, "little")
    return fixed + filename + extra


def test_eocd_comment_and_extra_zeroed():
    local = _local_header(b"name", b"ABCDEF") + b"filedata"
    eocd = b"PK\x05\x06" + b"\x00" * 18 + (5).to_bytes(2, "little") + b"hello"
    data = local + eocd
    cleaned, zeroed = m45.clean_archive_metadata(data)
    assert zeroed == 2
    assert len(cleaned) == len(data)
    assert b"ABCDEF" not in cleaned
    assert b"hello" not in cleaned
    assert b"name" in cleaned
    assert b"filedata" in cleaned


def test_clean_input_unchanged():
    data = b"definitely not a zip file"
    out, zeroed = m45.clean_archive_metadata(data)
    assert out == data and zeroed == 0


def test_malformed_does_not_raise():
    bads = [b"", b"PK\x05\x06", b"PK\x03\x04", b"PK\x05\x06" + b"\x00" * 10]
    for bad in bads:
        out, zeroed = m45.clean_archive_metadata(bad)
        assert isinstance(out, bytes) and isinstance(zeroed, int)


def test_stdlib_only():
    assert m45.stdlib_only() is True


def test_version_pin():
    assert m45.OUT_DEF_45_VERSION == "out-def-45.v1"
    assert m45.SCHEMA_PIN == "northstar.out-def-45.v1"
