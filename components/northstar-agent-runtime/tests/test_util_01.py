"""util_01 tests."""

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


m = _load("util_01")

def test_sha256_vector():
    assert m.sha256_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_blake2_length():
    assert len(m.blake2b_hex(b"data")) == 64


def test_sha256_file(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"hello")
    assert m.sha256_file(str(p)) == m.sha256_hex(b"hello")


def test_hash_chain_order():
    assert m.hash_chain(["a", "b"]) != m.hash_chain(["b", "a"])


def test_stdlib_only():
    assert m.stdlib_only() is True
