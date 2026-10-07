"""Tests for the FHE decision ledger (Simulated)."""

import ast
import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "fhe.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("fhe", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["fhe"] = module
    spec.loader.exec_module(module)
    return module


fhe = _load()


# 1. version/schema pins
def test_version_and_schema_pins():
    assert fhe.FHE_VERSION == "fhe.v1"
    assert fhe.SCHEMA_PIN == "northstar.fhe.v1"
    assert fhe.SCHEMES == ("bfv", "bgv", "ckks", "tfhe")
    assert fhe.OPS == ("add", "mul", "rotate", "bootstrap")


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(MOD.read_text())
    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "canonical_json",
    }
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= allowed, imports - allowed


# 3. keygen roundtrip
def test_keygen_roundtrip():
    f = fhe.FHE()
    rec = f.keygen("key-1", 1, scheme="ckks")
    assert rec.key_id == "key-1"
    assert rec.scheme == "ckks"
    assert rec.verify()
    assert f.key_record("key-1", 0).verify()


# 4. keygen bad inputs + duplicate + seq burn
def test_keygen_bad_inputs():
    f = fhe.FHE()
    with pytest.raises(fhe.DuplicateKeyError):
        f.keygen("k", 1)
        f.keygen("k", 2)
    for bad_id in ("", None, 123, "x" * 129):
        g = fhe.FHE()
        with pytest.raises((fhe.BadKeyError, TypeError)):
            g.keygen(bad_id, 1)
    g = fhe.FHE()
    with pytest.raises(fhe.BadKeyError):
        g.keygen("k", 1, scheme="rsa")
    assert g.stats(0)["n_keys"] == 0
    assert len(g.audit_log(0)) == 1  # one rejected row


# 5. encrypt roundtrip
def test_encrypt_roundtrip():
    f = fhe.FHE()
    f.keygen("key-1", 1)
    ct = f.encrypt("key-1", PIN, 2)
    assert ct.ciphertext_id == "ct-1"
    assert ct.key_id == "key-1"
    assert ct.plaintext_digest == PIN
    assert ct.verify()
    assert f.ciphertext_record("ct-1", 0).verify()


# 6. encrypt refusals (unknown key, bad digest) + seq burn
def test_encrypt_refusals():
    f = fhe.FHE()
    with pytest.raises(fhe.UnknownKeyError):
        f.encrypt("nope", PIN, 1)
    f.keygen("key-1", 2)
    for bad in ("raw-text", "sha256:zzz", PIN[:40], None):
        with pytest.raises(fhe.BadDigestError):
            f.encrypt("key-1", bad, f._seq + 1)
    assert f.stats(0)["n_ciphertexts"] == 0


# 7. compute roundtrip (add)
def test_compute_add_roundtrip():
    f = fhe.FHE()
    f.keygen("key-1", 1)
    a = f.encrypt("key-1", PIN, 2)
    b = f.encrypt("key-1", PIN2, 3)
    cmp_ = f.compute((a.ciphertext_id, b.ciphertext_id), "add", 4)
    assert cmp_.computation_id == "cmp-1"
    assert cmp_.op == "add"
    assert cmp_.input_ids == (a.ciphertext_id, b.ciphertext_id)
    assert cmp_.output_id == "ct-3"
    assert cmp_.verify()
    out = f.ciphertext_record(cmp_.output_id, 0)
    assert out.key_id == "key-1"


# 8. compute bad op / bad inputs
def test_compute_bad_inputs():
    f = fhe.FHE()
    f.keygen("key-1", 1)
    a = f.encrypt("key-1", PIN, 2)
    with pytest.raises(fhe.BadOpError):
        f.compute((a.ciphertext_id,), "divide", 3)
    with pytest.raises(fhe.UnknownCiphertextError):
        f.compute(("ct-999",), "add", 4)
    with pytest.raises(fhe.BadInputsError):
        f.compute((), "add", 5)
    with pytest.raises(fhe.BadInputsError):
        f.compute((a.ciphertext_id, a.ciphertext_id), "add", 6)


# 9. compute mixed-key refusal
def test_compute_mixed_key_refused():
    f = fhe.FHE()
    f.keygen("key-1", 1)
    f.keygen("key-2", 2)
    a = f.encrypt("key-1", PIN, 3)
    b = f.encrypt("key-2", PIN, 4)
    with pytest.raises(fhe.BadInputsError):
        f.compute((a.ciphertext_id, b.ciphertext_id), "add", 5)


# 10. decrypt pure read
def test_decrypt_pure_read():
    f = fhe.FHE()
    f.keygen("key-1", 1)
    ct = f.encrypt("key-1", PIN, 2)
    rows_before = len(f.audit_log(0))
    rep = f.decrypt(ct.ciphertext_id, "key-1", 2)  # same seq: read
    assert rep.plaintext_digest == PIN
    assert rep.verify()
    assert len(f.audit_log(2)) == rows_before  # no audit row consumed
    with pytest.raises(fhe.UnknownKeyError):
        f.decrypt(ct.ciphertext_id, "key-2", 2)
    with pytest.raises(fhe.UnknownCiphertextError):
        f.decrypt("ct-999", "key-1", 2)


# 11. seq discipline
def test_seq_discipline():
    f = fhe.FHE()
    with pytest.raises(fhe.SeqOrderError):
        f.keygen("k", 0)
    f.keygen("k", 1)
    with pytest.raises(fhe.SeqOrderError):
        f.keygen("k2", 1)  # rewind: raises bare
    with pytest.raises(fhe.SeqOrderError):
        f.keygen("k3", True)
    # malformed seq on reads raises without audit rows
    rows_before = len(f.audit_log(0))
    with pytest.raises(fhe.SeqOrderError):
        f.key_ids(-1)
    assert len(f.audit_log(0)) == rows_before


# 12. audit shapes + leak ban + bad kind
def test_audit_shapes_and_leak_ban():
    f = fhe.FHE()
    f.keygen("key-1", 1)
    ct = f.encrypt("key-1", PIN, 2)
    f.compute((ct.ciphertext_id,), "bootstrap", 3)
    try:
        f.encrypt("nope", PIN, 4)
    except fhe.UnknownKeyError:
        pass
    rows = f.audit_log(0)
    kinds = [r["kind"] for r in rows]
    assert kinds == ["key-registered", "encrypted", "computed", "rejected"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        detail = row["details"]
        for banned in ("plaintext", "key", "content", "payload", "raw", "value"):
            assert banned not in detail
    with pytest.raises(fhe.AuditKindError):
        fhe.fhe_audit_event("nope-kind", 9)


# 13. cross-instance digest determinism
def test_cross_instance_determinism():
    f1, f2 = fhe.FHE(), fhe.FHE()
    for f in (f1, f2):
        f.keygen("key-1", 1, scheme="bgv")
        ct = f.encrypt("key-1", PIN, 2)
        f.compute((ct.ciphertext_id,), "mul", 3)
    a1 = f1.computation_record("cmp-1", 0)
    a2 = f2.computation_record("cmp-1", 0)
    assert a1.digest == a2.digest
    # tamper breaks verify
    object.__setattr__(a1, "digest", "sha256:" + "00" * 32)
    assert not a1.verify()


# 14. views and stats
def test_views_and_stats():
    f = fhe.FHE()
    f.keygen("key-1", 1)
    ct = f.encrypt("key-1", PIN, 2)
    cmp_ = f.compute((ct.ciphertext_id,), "rotate", 3)
    assert f.key_ids(0) == ("key-1",)
    assert set(f.ciphertext_ids(0)) == {"ct-1", "ct-2"}
    assert f.computation_ids(0) == ("cmp-1",)
    st = f.stats(0)
    assert st["n_keys"] == 1 and st["n_ciphertexts"] == 2
    assert st["n_computations"] == 1 and st["n_audit_rows"] == 3
    assert f.computation_record(cmp_.computation_id, 0).verify()


# 15. main() subprocess check
def test_main_subprocess():
    out = subprocess.run(
        [sys.executable, str(MOD)], capture_output=True, text=True, timeout=60
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "fhe OK: keygen, encrypt, compute, decrypt, pins, audit"
