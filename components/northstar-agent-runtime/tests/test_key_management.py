"""15 tests for key_management.py (batch spec)."""
import ast
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import key_management
from key_management import (
    KeyManagement,
    key_management_audit_event,
    VERSION,
    SCHEMA,
    KeyManagementError,
    BadIdError,
    DuplicateKeyError,
    RevokedKeyError,
    UnknownKeyError,
    BadDigestError,
    BadAlgorithmError,
    BadReasonError,
    SeqOrderError,
    AuditKindError,
)

HERE = Path(__file__).resolve().parents[1]
MOD = HERE / "key_management.py"
GOOD_DIGEST = "sha256:" + "ab" * 32


def fresh() -> KeyManagement:
    return KeyManagement()


# 1. version/schema pins
def test_version_and_schema_pins():
    assert VERSION == "key-management.v1"
    assert SCHEMA == "northstar.key-management.v1"


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(MOD.read_text())
    allowed = {"hashlib", "threading", "dataclasses", "typing", "__future__",
               "re", "json", "canonical_json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# 3. create roundtrip + verify
def test_create_roundtrip():
    km = fresh()
    rec = km.create("k1", 1, algorithm="aes-256-gcm")
    assert rec.key_id == "k1"
    assert rec.algorithm == "aes-256-gcm"
    assert rec.version == 1
    assert rec.active is True
    assert rec.verify()
    assert km.key_ids(2) == ("k1",)
    assert km.stats(3)["keys"] == 1


# 4. duplicate create burns seq + books rejected
def test_duplicate_create_burns_seq():
    km = fresh()
    km.create("k1", 1)
    with pytest.raises(DuplicateKeyError):
        km.create("k1", 2)
    kinds = [r["kind"] for r in km.audit_log(3)]
    assert kinds == ["key-created", "rejected"]


# 5. create bad inputs (bad ids / bad algorithms / bad digests)
def test_create_bad_inputs():
    km = fresh()
    seq = 1
    bad_ids = ["", " ", "a b", "x" * 129, 123, None, True]
    for bad in bad_ids:
        seq += 1
        with pytest.raises((BadIdError, SeqOrderError)):
            km.create(bad, seq)
    for bad_algo in ["aes-128", "DES", "", 42, None, " AES-256-GCM"]:
        seq += 1
        with pytest.raises(BadAlgorithmError):
            km.create("ok-%d" % seq, seq, algorithm=bad_algo)
    for bad_digest in ["nope", "sha256:" + "zz" * 32, 42]:
        seq += 1
        with pytest.raises(BadDigestError):
            km.create("ok-%d" % seq, seq, key_digest=bad_digest)
    # every failed mutation consumed its seq and booked a rejected row
    kinds = [r["kind"] for r in km.audit_log(seq + 1)]
    assert all(k == "rejected" for k in kinds)
    assert len(kinds) == seq - 1


# 6. rotate roundtrip: version bumps, pins verify, ids never recycled
def test_rotate_roundtrip():
    km = fresh()
    km.create("k1", 1)
    rot = km.rotate("k1", 2)
    assert rot.rotation_id == "rot-1"
    assert rot.old_version == 1
    assert rot.new_version == 2
    assert rot.verify()
    rec = km.key_record("k1", 3)
    assert rec.version == 2 and rec.active is True
    assert km.rotation_ids(4) == ("rot-1",)
    rot2 = km.rotate("k1", 5)
    assert rot2.rotation_id == "rot-2"
    assert km.key_record("k1", 6).version == 3


# 7. rotate unknown / revoked fail closed
def test_rotate_unknown_and_revoked():
    km = fresh()
    km.create("k1", 1)
    with pytest.raises(UnknownKeyError):
        km.rotate("nope", 2)
    km.revoke("k1", 3)
    with pytest.raises(RevokedKeyError):
        km.rotate("k1", 4)
    # re-creating a revoked id fails closed too
    with pytest.raises(RevokedKeyError):
        km.create("k1", 5)


# 8. revoke terminality: second revoke / rotate / view of active flag
def test_revoke_terminal():
    km = fresh()
    km.create("k1", 1)
    rec = km.revoke("k1", 2, reason="key-compromised")
    assert rec.reason == "key-compromised"
    assert rec.version == 1
    assert rec.verify()
    with pytest.raises(RevokedKeyError):
        km.revoke("k1", 3)
    with pytest.raises(RevokedKeyError):
        km.rotate("k1", 4)
    assert km.key_record("k1", 5).active is False
    assert km.revoked_ids(6) == ("k1",)


# 9. revoke bad inputs: unknown key, bad reasons
def test_revoke_bad_inputs():
    km = fresh()
    km.create("k1", 1)
    with pytest.raises(UnknownKeyError):
        km.revoke("ghost", 2)
    seq = 2
    for bad in ["destroyed", "", "KEY-COMPROMISED", 42, None]:
        seq += 1
        with pytest.raises(BadReasonError):
            km.revoke("k1", seq, reason=bad)
    # a failed revoke consumed nothing; key still live and un-revoked
    assert km.key_record("k1", 4).active is True
    assert km.revoked_ids(5) == ()


# 10. seq discipline: rewind raises bare, malformed seqs raise
def test_seq_discipline():
    km = fresh()
    km.create("k1", 1)
    with pytest.raises(SeqOrderError):
        km.create("k2", 1)  # rewind: bare raise, no rejected row
    kinds = [r["kind"] for r in km.audit_log(2)]
    assert kinds == ["key-created"]
    for bad in [True, -1, "1", 1.5, None]:
        with pytest.raises(SeqOrderError):
            km.create("k2", bad)


# 11. view read purity: same seq twice, no audit rows, no consumption
def test_view_read_purity():
    km = fresh()
    km.create("k1", 1)
    assert km.key_record("k1", 5) is km.key_record("k1", 5)
    assert km.key_ids(5) == km.key_ids(5)
    assert km.stats(5)["keys"] == 1
    with pytest.raises(UnknownKeyError):
        km.key_record("ghost", 5)  # read-side failure: no audit row
    kinds = [r["kind"] for r in km.audit_log(6)]
    assert kinds == ["key-created"]


# 12. audit shapes + leak ban + bad kind
def test_audit_shapes_and_leak_ban():
    km = fresh()
    km.create("k1", 1, key_digest=GOOD_DIGEST)
    row = km.audit_log(2)[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["kind"] == "key-created"
    assert row["module"] == "key-management"
    assert "digest" in row
    # raw key material never crosses the audit boundary
    blob = str(row["detail"])
    for banned in ("key", "secret", "material", "plaintext", "bytes"):
        assert banned not in row["detail"], banned
    assert blob  # detail exists
    with pytest.raises(AuditKindError):
        key_management_audit_event("nope", 1)
    with pytest.raises(AuditKindError):
        key_management_audit_event("key-created", 1,
                                   {"key": "supersecret"})
    with pytest.raises(AuditKindError):
        key_management_audit_event("key-created", 1,
                                   {"raw": b"bytes"})


# 13. rotation records expose minted ids; all reasons in vocabulary
def test_reason_and_rotation_vocabulary():
    km = fresh()
    km.create("k1", 1)
    km.rotate("k1", 2)
    rec = km.rotation_record("rot-1", 3)
    assert rec.key_id == "k1"
    with pytest.raises(UnknownKeyError):
        km.rotation_record("rot-999", 4)
    for reason in ("manual", "key-compromised", "rotation-policy",
                   "employee-departure", "suspected-leak", "superseded"):
        km2 = fresh()
        km2.create("k", 1)
        rec = km2.revoke("k", 2, reason=reason)
        assert rec.reason == reason and rec.verify()


# 14. cross-instance digest determinism + tamper breaks verify
def test_determinism_and_tamper():
    a, b = fresh(), fresh()
    ra = a.create("k1", 1, key_digest=GOOD_DIGEST)
    rb = b.create("k1", 1, key_digest=GOOD_DIGEST)
    assert ra.digest == rb.digest
    obj = fresh()
    rec = obj.create("k1", 1)
    object.__setattr__(rec, "version", 99)
    assert rec.verify() is False


# 15. main() subprocess self-check
def test_main_subprocess():
    proc = subprocess.run([sys.executable, str(MOD)], capture_output=True,
                          text=True)
    assert proc.returncode == 0, proc.stderr
    assert "key-management OK: create, rotate, revoke, pins, audit" \
        in proc.stdout
