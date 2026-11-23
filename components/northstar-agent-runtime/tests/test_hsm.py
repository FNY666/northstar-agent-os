"""Targeted tests for the HSM operations ledger."""

import ast
import hashlib
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MODULE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(MODULE_DIR))

import hsm as hsm_mod  # noqa: E402
from hsm import HSM  # noqa: E402


def _digest(text):
    return hsm_mod._digest_pin({"t": text})


def test_version_and_schema_pins():
    assert hsm_mod.VERSION == "hsm.v1"
    assert hsm_mod.SCHEMA == "northstar.hsm.v1"


def test_stdlib_only_ast():
    src = (MODULE_DIR / "hsm.py").read_text()
    tree = ast.parse(src)
    allowed = {"__future__", "dataclasses", "hashlib", "json", "re",
               "threading", "typing", "canonical_json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_register_partition_roundtrip_and_verify():
    h = HSM()
    rec = h.register_partition("slot-0", 0)
    assert rec.partition_id == "slot-0"
    assert rec.verify()
    assert rec.as_dict()["schema"] == hsm_mod.SCHEMA
    assert h.partition_record("slot-0", 1) is rec
    assert h.partition_ids(2) == ("slot-0",)


def test_register_partition_duplicate_and_bad_ids_seq_burn():
    h = HSM()
    h.register_partition("ok", 0)
    n_rejected = 0
    for seq, bad in ((1, "ok"), (2, ""), (3, "a b"), (4, None), (5, 123)):
        with pytest.raises(hsm_mod.HSMError):
            h.register_partition(bad, seq)
        n_rejected += 1
    assert h.stats(6)["rejected"] == n_rejected
    assert h.partition_ids(7) == ("ok",)


def test_generate_roundtrip_and_verify():
    h = HSM()
    h.register_partition("slot-0", 0)
    rec = h.generate("slot-0", "k-1", "ed25519-sim", 1)
    assert rec.key_id == "k-1"
    assert rec.algorithm == "ed25519-sim"
    assert rec.material_pin.startswith("sha256:")
    assert rec.verify()
    assert h.key_record("k-1", 2) is rec
    assert h.key_ids(3) == ("k-1",)


def test_generate_bad_inputs_seq_burn():
    h = HSM()
    h.register_partition("slot-0", 0)
    h.generate("slot-0", "k-1", "ed25519-sim", 1)
    n_rejected = 0
    cases = [
        (2, "nope", "k-2", "ed25519-sim"),      # unknown partition
        (3, "slot-0", "k-1", "ed25519-sim"),    # duplicate key
        (4, "slot-0", "k-2", "rot13-sim"),      # bad algorithm
        (5, "slot-0", "", "ed25519-sim"),       # empty key id
        (6, "slot-0", "k-2", "ed25519-sim"),    # ok (consumes, no reject)
    ]
    for seq, part, key, algo in cases:
        if seq == 6:
            h.generate(part, key, algo, seq)
        else:
            with pytest.raises(hsm_mod.HSMError):
                h.generate(part, key, algo, seq)
            n_rejected += 1
    assert h.stats(7)["rejected"] == n_rejected
    assert h.key_ids(8) == ("k-1", "k-2")


def test_sign_roundtrip_and_verify():
    h = HSM()
    h.register_partition("slot-0", 0)
    h.generate("slot-0", "k-sign", "hmac-sha256", 1)
    md = _digest("hello")
    rec = h.sign("slot-0", "k-sign", md, 2)
    assert rec.op_id == "sig-1"
    assert rec.message_digest == md
    assert rec.verify()
    assert h.operation_record("sig-1", 3) is rec
    assert h.operations_for("k-sign", 4) == (rec,)


def test_sign_bad_inputs_seq_burn():
    h = HSM()
    h.register_partition("slot-0", 0)
    h.generate("slot-0", "k-sign", "ed25519-sim", 1)
    h.generate("slot-0", "k-enc", "aes-256-gcm-sim", 2)
    md = _digest("x")
    n_rejected = 0
    with pytest.raises(hsm_mod.UnknownKeyError):
        h.sign("slot-0", "nope", md, 3)
    n_rejected += 1
    with pytest.raises(hsm_mod.WrongKeyUseError):  # encryption key signs
        h.sign("slot-0", "k-enc", md, 4)
    n_rejected += 1
    with pytest.raises(hsm_mod.BadDigestError):  # raw message refused
        h.sign("slot-0", "k-sign", "hello", 5)
    n_rejected += 1
    with pytest.raises(hsm_mod.UnknownPartitionError):
        h.sign("other", "k-sign", md, 6)
    n_rejected += 1
    assert h.stats(7)["rejected"] == n_rejected
    assert h.stats(8)["signatures"] == 0


def test_decrypt_roundtrip_and_verify():
    h = HSM()
    h.register_partition("slot-0", 0)
    h.generate("slot-0", "k-enc", "rsa-oaep-sim", 1)
    cd = _digest("ciphertext")
    rec = h.decrypt("slot-0", "k-enc", cd, 2)
    assert rec.op_id == "dec-1"
    assert rec.ciphertext_digest == cd
    assert rec.verify()
    assert h.stats(3)["decryptions"] == 1


def test_decrypt_bad_inputs_seq_burn():
    h = HSM()
    h.register_partition("slot-0", 0)
    h.generate("slot-0", "k-sign", "ed25519-sim", 1)
    h.generate("slot-0", "k-enc", "aes-256-gcm-sim", 2)
    cd = _digest("ct")
    n_rejected = 0
    with pytest.raises(hsm_mod.WrongKeyUseError):  # signing key decrypts
        h.decrypt("slot-0", "k-sign", cd, 3)
    n_rejected += 1
    with pytest.raises(hsm_mod.UnknownKeyError):
        h.decrypt("slot-0", "nope", cd, 4)
    n_rejected += 1
    with pytest.raises(hsm_mod.BadDigestError):
        h.decrypt("slot-0", "k-enc", "not-a-pin", 5)
    n_rejected += 1
    assert h.stats(6)["rejected"] == n_rejected


def test_revoke_terminality_and_no_recycle():
    h = HSM()
    h.register_partition("slot-0", 0)
    h.generate("slot-0", "k-1", "ed25519-sim", 1)
    rec = h.revoke("k-1", 2, reason="rotation")
    assert rec.verify()
    assert h.revoked_ids(3) == ("k-1",)
    md = _digest("m")
    with pytest.raises(hsm_mod.RevokedKeyError):
        h.sign("slot-0", "k-1", md, 4)
    with pytest.raises(hsm_mod.RevokedKeyError):
        h.revoke("k-1", 5)
    with pytest.raises(hsm_mod.RetiredKeyError):  # id never recycled
        h.generate("slot-0", "k-1", "ed25519-sim", 6)
    assert h.revocation_record("k-1", 7) is rec
    assert h.stats(8)["rejected"] == 3


def test_seq_discipline_rewind_bare_and_malformed():
    h = HSM()
    h.register_partition("slot-0", 0)
    with pytest.raises(hsm_mod.SeqOrderError):  # rewind raises bare
        h.register_partition("slot-1", 0)
    for bad in (True, "1", -1, 1.5, None):
        with pytest.raises(hsm_mod.SeqOrderError):
            h.register_partition("slot-x", bad)
    assert h.stats(1)["rejected"] == 0  # bare raises book no rows
    assert h.partition_ids(2) == ("slot-0",)


def test_view_read_purity_and_stats():
    h = HSM()
    h.register_partition("slot-0", 0)
    h.generate("slot-0", "k-sign", "ed25519-sim", 1)
    h.generate("slot-0", "k-enc", "aes-256-gcm-sim", 2)
    md, cd = _digest("m"), _digest("c")
    h.sign("slot-0", "k-sign", md, 3)
    h.decrypt("slot-0", "k-enc", cd, 4)
    n_rows = len(h.audit_log(5))
    h.stats(6); h.stats(7)  # same seq range, views add no rows
    h.key_ids(8); h.operations_for("k-sign", 9)
    assert len(h.audit_log(10)) == n_rows
    st = h.stats(11)
    assert st["partitions"] == 1 and st["keys"] == 2
    assert st["signatures"] == 1 and st["decryptions"] == 1
    assert st["revoked"] == 0 and st["rejected"] == 0


def test_audit_shapes_leak_ban_and_bad_kind():
    h = HSM()
    h.register_partition("slot-0", 0)
    h.generate("slot-0", "k-1", "ed25519-sim", 1)
    h.sign("slot-0", "k-1", _digest("m"), 2)
    rows = h.audit_log(3)
    kinds = [r["kind"] for r in rows]
    assert kinds == ["hsm.partition-registered", "hsm.key-generated",
                     "hsm.signed"]
    for r in rows:
        assert r["audit_version"] == "audit.ndjson/1"
        assert r["schema"] == hsm_mod.SCHEMA
        text = str(r)
        for banned in ("message", "plaintext", "material", "secret"):
            assert f"'{banned}'" not in text
    with pytest.raises(hsm_mod.AuditKindError):
        hsm_mod.hsm_audit_event("bogus", {}, 4)
    with pytest.raises(hsm_mod.AuditKindError):
        hsm_mod.hsm_audit_event("signed", {"message": "x"}, 4)


def test_cross_instance_digest_determinism_and_main():
    a, b = HSM(), HSM()
    for h in (a, b):
        h.register_partition("slot-0", 0)
        h.generate("slot-0", "k-1", "ed25519-sim", 1)
        h.sign("slot-0", "k-1", _digest("m"), 2)
    assert (a.key_record("k-1", 3).digest ==
            b.key_record("k-1", 3).digest)
    assert (a.operation_record("sig-1", 4).digest ==
            b.operation_record("sig-1", 4).digest)
    # tamper breaks verify
    rec = a.key_record("k-1", 5)
    import dataclasses
    forged = dataclasses.replace(rec, key_id="forged")
    assert not forged.verify()
    # 4-thread read smoke
    errs = []
    def _reader():
        try:
            for _ in range(50):
                a.key_record("k-1", 6)
                a.stats(7)
        except Exception as e:  # pragma: no cover
            errs.append(e)
    ths = [threading.Thread(target=_reader) for _ in range(4)]
    for t in ths: t.start()
    for t in ths: t.join()
    assert not errs
    # main() subprocess check
    proc = subprocess.run([sys.executable, str(MODULE_DIR / "hsm.py")],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0
    assert "hsm OK" in proc.stdout
