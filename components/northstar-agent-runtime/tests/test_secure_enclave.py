"""Tests for secure_enclave (enclave lifecycle registry, simulated)."""

import ast
import hashlib
import subprocess
import sys
import threading

import pytest

from secure_enclave import (
    VERSION,
    SCHEMA,
    TEE_TYPES,
    SecureEnclaveError,
    BadIdError,
    DuplicateEnclaveError,
    UnknownEnclaveError,
    RetiredEnclaveError,
    BadTeeTypeError,
    BadNonceError,
    BadLabelError,
    BadDataError,
    UnknownSealError,
    SealDeniedError,
    VerificationError,
    SeqOrderError,
    AuditKindError,
    ProvisionRecord,
    AttestationDecision,
    SealRecord,
    UnsealRecord,
    RetireRecord,
    SecureEnclave,
    secure_enclave_audit_event,
)

STDLIB_ALLOW = {
    "hashlib", "json", "threading", "dataclasses", "typing",
    "__future__", "enclave_interface",
}


def _meas(tag: bytes = b"test-enclave-code") -> str:
    return "sha256:" + hashlib.sha256(tag).hexdigest()


def _reg() -> SecureEnclave:
    return SecureEnclave()


def _provisioned(**kw):
    reg = _reg()
    base = {"enclave_id": "enc-1", "tee_type": "software", "measurement": _meas()}
    base.update(kw)
    reg.provision(base["enclave_id"], base["tee_type"], base["measurement"], 1)
    return reg


# 1. version / schema pins
def test_pins():
    assert VERSION == "secure-enclave.v1"
    assert SCHEMA == "northstar.secure-enclave.v1"
    assert set(TEE_TYPES) == {"sgx", "sev-snp", "tdx", "software"}


# 2. stdlib-only AST check
def test_stdlib_only():
    import secure_enclave
    tree = ast.parse(open(secure_enclave.__file__).read())
    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            mods.add(node.module.split(".")[0])
    assert mods <= STDLIB_ALLOW, mods - STDLIB_ALLOW


# 3. provision roundtrip + verify
def test_provision_roundtrip():
    reg = _reg()
    rec = reg.provision("enc-1", "software", _meas(), 1)
    assert isinstance(rec, ProvisionRecord)
    rec.verify()
    assert rec.enclave_id == "enc-1"
    assert rec.as_dict()["schema"] == SCHEMA
    got = reg.provision_record("enc-1", 2)
    assert got.digest == rec.digest
    assert reg.enclave_ids(2) == ("enc-1",)


# 4. provision bad inputs + duplicate + seq-burn + rejected rows
def test_provision_bad_inputs():
    reg = _reg()
    seq = 0
    seq += 1
    reg.provision("enc-ok", "software", _meas(), seq)
    rejected_before = reg.stats(seq + 1)["rejected"]
    bad = [
        ("", "software", _meas()),           # empty id
        (123, "software", _meas()),           # non-str id
        ("enc-x", "quantum", _meas()),        # bad tee type
        ("enc-x", "software", "nope"),        # bad measurement
        ("enc-x", "software", ""),            # empty measurement
    ]
    n_bad = len(bad)
    for eid, tt, mm in bad:
        seq += 1
        with pytest.raises(SecureEnclaveError):
            reg.provision(eid, tt, mm, seq)
    # duplicate
    seq += 1
    with pytest.raises(DuplicateEnclaveError):
        reg.provision("enc-ok", "software", _meas(), seq)
    assert reg.stats(seq + 1)["rejected"] == rejected_before + n_bad + 1
    # frozen
    rec = reg.provision_record("enc-ok", seq + 1)
    with pytest.raises(Exception):
        rec.enclave_id = "x"  # noqa


# 5. attest roundtrip: attested=True, reason==""
def test_attest_roundtrip():
    reg = _provisioned()
    dec = reg.attest("enc-1", b"nonce-1", 2)
    assert isinstance(dec, AttestationDecision)
    dec.verify()
    assert dec.attested is True
    assert dec.reason == ""
    assert dec.att_id == "att-1"
    assert dec.nonce_digest == "sha256:" + hashlib.sha256(b"nonce|" + b"nonce-1").hexdigest()
    assert b"nonce-1" not in repr(dec.as_dict()).encode()
    assert reg.attestations_for("enc-1", 3) == ("att-1",)
    assert reg.attestation_record("att-1", 3).digest == dec.digest


# 6. attestation mismatch is data, not raised
def test_attest_mismatch_as_data():
    reg = _provisioned()
    wrong = "sha256:" + hashlib.sha256(b"wrong-code").hexdigest()
    dec = reg.attest("enc-1", b"nonce-2", 2, expected_measurement=wrong)
    assert dec.attested is False
    assert dec.reason == "measurement-mismatch"
    dec.verify()  # pins still verify; the ledger is intact


# 7. attest bad inputs
def test_attest_bad_inputs():
    reg = _provisioned()
    seq = 1
    seq += 1
    with pytest.raises(UnknownEnclaveError):
        reg.attest("enc-nope", b"n", seq)
    for bad in (b"", "str-nonce", None, 123):
        seq += 1
        with pytest.raises(BadNonceError):
            reg.attest("enc-1", bad, seq)
    seq += 1
    with pytest.raises(SecureEnclaveError):
        reg.attest("enc-1", b"n", seq, expected_measurement="nope")
    seq += 1
    reg.retire("enc-1", seq)
    seq += 1
    with pytest.raises(RetiredEnclaveError):
        reg.attest("enc-1", b"n", seq)


# 8. seal roundtrip + digest pins
def test_seal_roundtrip():
    reg = _provisioned()
    rec = reg.seal("enc-1", "api-key", b"super-secret", 2)
    assert isinstance(rec, SealRecord)
    rec.verify()
    assert rec.seal_id == "seal-1"
    assert rec.data_digest == "sha256:" + hashlib.sha256(b"data|super-secret").hexdigest()
    assert b"super-secret" not in repr(rec.as_dict()).encode()
    assert reg.seal_record("seal-1", 3).digest == rec.digest


# 9. seal bad inputs
def test_seal_bad_inputs():
    reg = _provisioned()
    seq = 1
    seq += 1
    with pytest.raises(UnknownEnclaveError):
        reg.seal("enc-nope", "l", b"d", seq)
    seq += 1
    with pytest.raises(BadLabelError):
        reg.seal("enc-1", "", b"d", seq)
    for bad in (b"", "text", None):
        seq += 1
        with pytest.raises(BadDataError):
            reg.seal("enc-1", "l", bad, seq)
    seq += 1
    reg.retire("enc-1", seq)
    seq += 1
    with pytest.raises(RetiredEnclaveError):
        reg.seal("enc-1", "l", b"d", seq)


# 10. unseal happy path with fresh attestation
def test_unseal_happy_path():
    reg = _provisioned()
    seal = reg.seal("enc-1", "api-key", b"super-secret", 2)
    dec = reg.attest("enc-1", b"nonce-fresh", 3)
    assert dec.seq >= seal.seq
    plaintext, unseal = reg.unseal("enc-1", seal.seal_id, 4)
    assert plaintext == b"super-secret"
    assert isinstance(unseal, UnsealRecord)
    unseal.verify()
    assert unseal.unseal_id == "unseal-1"
    assert unseal.plaintext_digest == "sha256:" + hashlib.sha256(b"plaintext|super-secret").hexdigest()
    assert b"super-secret" not in repr(unseal.as_dict()).encode()
    assert reg.unseal_record("unseal-1", 5).digest == unseal.digest


# 11. unseal denied without fresh attestation
def test_unseal_denied_no_fresh_attestation():
    reg = _provisioned()
    reg.attest("enc-1", b"old", 2)  # stale: booked before the seal
    seal = reg.seal("enc-1", "api-key", b"super-secret", 3)
    before = reg.stats(4)["rejected"]
    with pytest.raises(SealDeniedError):
        reg.unseal("enc-1", seal.seal_id, 4)
    assert reg.stats(5)["rejected"] == before + 1
    # a fresh attestation (seq >= seal seq) authorizes
    reg.attest("enc-1", b"fresh", 6)
    pt, _ = reg.unseal("enc-1", seal.seal_id, 7)
    assert pt == b"super-secret"


# 12. unseal unknown seal / wrong enclave / retired
def test_unseal_bad_inputs():
    reg = _provisioned()
    seq = 1
    seq += 1
    seal = reg.seal("enc-1", "k", b"d", seq)
    seq += 1
    reg.provision("enc-2", "software", _meas(b"other"), seq)
    seq += 1
    with pytest.raises(UnknownSealError):
        reg.unseal("enc-1", "seal-999", seq)
    seq += 1
    with pytest.raises(UnknownSealError):
        reg.unseal("enc-2", seal.seal_id, seq)  # belongs to enc-1
    seq += 1
    reg.retire("enc-1", seq)
    seq += 1
    with pytest.raises(RetiredEnclaveError):
        reg.unseal("enc-1", seal.seal_id, seq)


# 13. retire terminality
def test_retire_terminality():
    reg = _provisioned()
    seq = 1
    seq += 1
    ret = reg.retire("enc-1", seq, reason="decommissioned")
    assert isinstance(ret, RetireRecord)
    ret.verify()
    assert ret.reason == "decommissioned"
    # re-retire / re-provision refused; ids never recycled
    seq += 1
    with pytest.raises(RetiredEnclaveError):
        reg.retire("enc-1", seq)
    seq += 1
    with pytest.raises(RetiredEnclaveError):
        reg.provision("enc-1", "software", _meas(), seq)
    seq += 1
    with pytest.raises(RetiredEnclaveError):
        reg.seal("enc-1", "k", b"d", seq)
    seq += 1
    with pytest.raises(UnknownEnclaveError):
        reg.retire("enc-nope", seq)
    # views still work
    assert reg.provision_record("enc-1", seq + 1).enclave_id == "enc-1"
    assert reg.stats(seq + 1)["retired"] == 1


# 14. seq discipline: rewind bare, malformed refused, burn on failure, views pure
def test_seq_discipline():
    reg = _reg()
    reg.provision("enc-1", "software", _meas(), 1)
    # rewind raises bare, consumes nothing, no rejected row
    n_rej = reg.stats(2)["rejected"]
    with pytest.raises(SeqOrderError):
        reg.provision("enc-2", "software", _meas(), 1)
    assert reg.stats(2)["rejected"] == n_rej
    assert reg.enclave_ids(2) == ("enc-1",)
    # malformed seqs
    for bad in (True, "2", 1.5, -1, None):
        with pytest.raises((SeqOrderError, TypeError, ValueError)):
            reg.provision("enc-x", "software", _meas(), bad)
    # failed mutation consumes seq: next good call must advance
    reg.provision("enc-2", "software", _meas(), 3)  # skipped seq 2 is burned, still legal
    # views are pure reads: same seq twice, no consumption, no audit rows
    n_audit = len(reg.audit_log(4))
    reg.stats(4)
    reg.enclave_ids(4)
    assert len(reg.audit_log(4)) == n_audit


# 15. audit shapes, leak ban, bad kind, main(), determinism, concurrency
def test_audit_and_misc():
    reg = _provisioned()
    rec = reg.seal("enc-1", "k", b"d", 2)
    reg.attest("enc-1", b"n1", 3)
    reg.unseal("enc-1", rec.seal_id, 4)
    reg.retire("enc-1", 5)
    kinds = [e["event_type"] for e in reg.audit_log(6)]
    assert kinds == [
        "secure-enclave.provisioned",
        "secure-enclave.sealed",
        "secure-enclave.attested",
        "secure-enclave.unsealed",
        "secure-enclave.retired",
    ]
    for e in reg.audit_log(6):
        assert e["schema_version"] == "northstar.audit.v1"
        for raw_key in ("nonce", "data", "plaintext", "payload", "raw", "value",
                        "text", "message", "content", "secret", "key", "quote",
                        "ciphertext", "bytes"):
            assert raw_key not in e["detail"]
    # raw nonce bytes never appear anywhere in the audit trail
    assert "n1" not in repr(reg.audit_log(6))
    with pytest.raises(AuditKindError):
        secure_enclave_audit_event("nope", 1)
    with pytest.raises(ValueError):
        secure_enclave_audit_event("secure-enclave.sealed", 1, detail={"data": b"x"})
    # cross-instance determinism
    r2 = SecureEnclave()
    r2.provision("enc-1", "software", _meas(), 1)
    assert r2.provision_record("enc-1", 2).digest == reg.provision_record("enc-1", 6).digest
    # tamper breaks verify
    rec2 = reg.provision_record("enc-1", 6)
    object.__setattr__(rec2, "digest", "sha256:" + "0" * 64)
    with pytest.raises(VerificationError):
        rec2.verify()
    # 8-thread read smoke
    errs = []
    def rd():
        try:
            reg.stats(7)
            reg.audit_log(7)
        except Exception as e:  # noqa
            errs.append(e)
    ts = [threading.Thread(target=rd) for _ in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not errs


def test_main_subprocess():
    r = subprocess.run(
        [sys.executable, "secure_enclave.py"],
        capture_output=True, text=True, cwd=".",
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "secure-enclave OK: provision, attest, seal, unseal, retire"
