"""Tests for zero_knowledge.py — ZK proving-system lifecycle bookkeeping."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import zero_knowledge
from zero_knowledge import (
    AUDIT_KINDS,
    CEREMONIES,
    SCHEMA,
    VERSION,
    AuditKindError,
    BadCeremonyError,
    BadDigestError,
    BadIdError,
    BadReasonError,
    BadWasteError,
    BadWitnessError,
    DuplicateCircuitError,
    DuplicateProofError,
    RetiredCircuitError,
    SeqOrderError,
    UnknownCircuitError,
    UnknownProofError,
    ZeroKnowledge,
    zero_knowledge_audit_event,
)

COMP = Path(__file__).resolve().parent.parent

CONSTRAINT = "sha256:" + "ab" * 32


def test_01_version_and_schema_pins():
    assert zero_knowledge.VERSION == "zero-knowledge.v1"
    assert zero_knowledge.SCHEMA == "northstar.zero-knowledge.v1"
    assert VERSION == "zero-knowledge.v1"
    assert SCHEMA == "northstar.zero-knowledge.v1"
    assert "zero-knowledge.rejected" in AUDIT_KINDS
    assert len(CEREMONIES) == 5
    assert "transparent" in CEREMONIES and "trusted-setup" in CEREMONIES


def test_02_stdlib_only_ast_check():
    src = (COMP / "zero_knowledge.py").read_text()
    tree = ast.parse(src)
    allowed = {
        "hashlib",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "json",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                assert top in allowed, f"import {alias.name} not allowed"
        elif isinstance(node, ast.ImportFrom):
            top = (node.module or "").split(".")[0]
            assert top in allowed, f"from-import {node.module} not allowed"


def test_03_setup_roundtrip_and_verify():
    zk = ZeroKnowledge()
    rec = zk.setup("range-proof", 1, ceremony="transparent",
                   constraint_digest=CONSTRAINT)
    assert rec.circuit_id == "range-proof"
    assert rec.ceremony == "transparent"
    assert rec.toxic_waste == "n/a"
    assert rec.constraint_digest == CONSTRAINT
    assert rec.digest.startswith("sha256:")
    assert rec.proving_key_digest.startswith("sha256:")
    assert rec.verification_key_digest.startswith("sha256:")
    assert rec.proving_key_digest != rec.verification_key_digest
    assert rec.verify() is True
    d = rec.as_dict()
    assert d["schema"] == SCHEMA and d["version"] == VERSION
    assert zk.setup_record("range-proof", 2) == rec
    assert zk.circuit_ids(3) == ("range-proof",)
    log = zk.audit_log(4)
    assert len(log) == 1 and log[0]["kind"] == "setup-completed"
    # trusted-setup ceremony books destroyed toxic waste
    rec2 = zk.setup("groth16", 5, ceremony="trusted-setup",
                    constraint_digest=CONSTRAINT,
                    participants=("alice", "bob"), toxic_waste="destroyed")
    assert rec2.verify() is True
    assert rec2.participants == ("alice", "bob")  # sorted
    assert rec2.toxic_waste == "destroyed"


def test_04_setup_refusals_and_seq_burn():
    zk = ZeroKnowledge()
    zk.setup("c1", 1, ceremony="transparent", constraint_digest=CONSTRAINT)
    # duplicate circuit
    with pytest.raises(DuplicateCircuitError):
        zk.setup("c1", 2, ceremony="transparent", constraint_digest=CONSTRAINT)
    # bad ceremony vocabulary
    with pytest.raises(BadCeremonyError):
        zk.setup("c2", 3, ceremony="laser-show", constraint_digest=CONSTRAINT)
    # transparent ceremony requires toxic_waste == "n/a"
    with pytest.raises(BadWasteError):
        zk.setup("c3", 4, ceremony="transparent",
                 constraint_digest=CONSTRAINT, toxic_waste="destroyed")
    # trusted-setup requires toxic_waste == "destroyed"
    with pytest.raises(BadWasteError):
        zk.setup("c4", 5, ceremony="trusted-setup",
                 constraint_digest=CONSTRAINT, toxic_waste="n/a")
    # constraint digest must be a sha256 pin
    with pytest.raises(BadDigestError):
        zk.setup("c5", 6, ceremony="transparent", constraint_digest="not-a-pin")
    # bad circuit ids
    with pytest.raises(BadIdError):
        zk.setup("", 7, ceremony="transparent", constraint_digest=CONSTRAINT)
    with pytest.raises(BadIdError):
        zk.setup(True, 8, ceremony="transparent", constraint_digest=CONSTRAINT)
    # failed mutations consumed their seqs: 7 failures + 1 success = seq 8 claimed
    log = zk.audit_log(9)
    rejected = [e for e in log if e["kind"] == "zero-knowledge.rejected"]
    assert len(rejected) == 7
    assert zk.stats(9)["circuits"] == 1


def test_05_prove_roundtrip_and_verify():
    zk = ZeroKnowledge()
    zk.setup("range-proof", 1, ceremony="transparent",
             constraint_digest=CONSTRAINT)
    proof = zk.prove("range-proof", "proof-1",
                     {"x": 3, "limit": 10},
                     {"secret_note": "correct-horse-battery-staple"}, 2)
    assert proof.proof_id == "proof-1"
    assert proof.circuit_id == "range-proof"
    assert proof.proof_pin.startswith("sha256:")
    assert proof.statement_digest.startswith("sha256:")
    assert proof.witness_pin.startswith("sha256:")
    assert proof.verify() is True
    d = proof.as_dict()
    assert d["schema"] == SCHEMA and d["version"] == VERSION
    # raw witness never enters the record
    assert "correct-horse-battery-staple" not in repr(d)
    assert "secret_note" not in repr(d)
    assert zk.proof_record("proof-1", 3) == proof
    assert zk.proof_ids(4) == ("proof-1",)
    log = zk.audit_log(5)
    assert log[-1]["kind"] == "proved"
    # proofs are deterministic: same statement + witness -> same pins
    proof2 = ZeroKnowledge()
    proof2.setup("range-proof", 1, ceremony="transparent",
                 constraint_digest=CONSTRAINT)
    p2 = proof2.prove("range-proof", "proof-1",
                      {"x": 3, "limit": 10},
                      {"secret_note": "correct-horse-battery-staple"}, 2)
    assert p2.proof_pin == proof.proof_pin
    assert p2.statement_digest == proof.statement_digest


def test_06_prove_refusals_and_seq_burn():
    zk = ZeroKnowledge()
    zk.setup("c1", 1, ceremony="transparent", constraint_digest=CONSTRAINT)
    zk.prove("c1", "p1", {"x": 1}, {"w": 2}, 2)
    # unknown circuit
    with pytest.raises(UnknownCircuitError):
        zk.prove("nope", "p2", {"x": 1}, {"w": 2}, 3)
    # duplicate proof id
    with pytest.raises(DuplicateProofError):
        zk.prove("c1", "p1", {"x": 1}, {"w": 2}, 4)
    # witness must be a mapping
    with pytest.raises(BadWitnessError):
        zk.prove("c1", "p3", {"x": 1}, ["not", "a", "mapping"], 5)
    # witness with unencodable values refused
    with pytest.raises(BadWitnessError):
        zk.prove("c1", "p4", {"x": 1}, {"w": object()}, 6)
    # bad proof id
    with pytest.raises(BadIdError):
        zk.prove("c1", "", {"x": 1}, {"w": 2}, 7)
    log = zk.audit_log(8)
    rejected = [e for e in log if e["kind"] == "zero-knowledge.rejected"]
    assert len(rejected) == 5
    assert zk.stats(8)["proofs"] == 1


def test_07_verify_report_semantics():
    zk = ZeroKnowledge()
    zk.setup("c1", 1, ceremony="transparent", constraint_digest=CONSTRAINT)
    zk.prove("c1", "p1", {"x": 1}, {"w": 2}, 2)
    rep = zk.verify("p1", 3)
    assert rep.verify() is True
    assert rep.valid is True
    assert rep.integrity_ok is True
    assert rep.circuit_retired is False
    assert rep.circuit_id == "c1"
    assert rep.statement_digest.startswith("sha256:")
    # unknown proof reports valid=False as data, never raised
    rep2 = zk.verify("never-seen", 4)
    assert rep2.verify() is True
    assert rep2.valid is False
    assert rep2.integrity_ok is True
    assert rep2.circuit_id == ""
    # statement substitution: binding is per statement, so a proof bound
    # to different public inputs cannot verify as the same statement
    zk.prove("c1", "p2", {"x": 999}, {"w": 2}, 5)
    r1 = zk.verify("p1", 6)
    r2 = zk.verify("p2", 6)
    assert r1.statement_digest != r2.statement_digest
    assert r1.valid is True and r2.valid is True


def test_08_tamper_detection_as_data():
    zk = ZeroKnowledge()
    zk.setup("c1", 1, ceremony="transparent", constraint_digest=CONSTRAINT)
    zk.prove("c1", "p1", {"x": 1}, {"w": 2}, 2)
    # corrupt a booked record in place: ledger pins must catch it
    import dataclasses

    proof = zk.proof_record("p1", 3)
    tampered = dataclasses.replace(proof, proof_pin="sha256:" + "00" * 32)
    zk._proofs["p1"] = tampered
    rep = zk.verify("p1", 4)
    assert rep.verify() is True  # the report itself is well-formed
    assert rep.valid is False and rep.integrity_ok is False


def test_09_retire_terminality():
    zk = ZeroKnowledge()
    zk.setup("c1", 1, ceremony="transparent", constraint_digest=CONSTRAINT)
    zk.prove("c1", "p1", {"x": 1}, {"w": 2}, 2)
    ret = zk.retire("c1", 3, reason="superseded")
    assert ret.verify() is True
    assert zk.retired_ids(4) == ("c1",)
    # prove after retire refused fail-closed
    with pytest.raises(RetiredCircuitError):
        zk.prove("c1", "p2", {"x": 1}, {"w": 2}, 5)
    # retired id never recycled
    with pytest.raises(RetiredCircuitError):
        zk.setup("c1", 6, ceremony="transparent", constraint_digest=CONSTRAINT)
    # booked proofs stay verifiable; report flags the retirement as data
    rep = zk.verify("p1", 7)
    assert rep.verify() is True
    assert rep.integrity_ok is True
    assert rep.circuit_retired is True
    assert rep.valid is False
    # unknown circuit retire refused
    with pytest.raises(UnknownCircuitError):
        zk.retire("nope", 8)
    # bad reason refused
    with pytest.raises(BadReasonError):
        zk.retire("c1", 9, reason="because")


def test_10_witness_banned_from_records_and_audit():
    zk = ZeroKnowledge()
    zk.setup("c1", 1, ceremony="transparent", constraint_digest=CONSTRAINT)
    secret = "super-secret-witness-value-12345"
    proof = zk.prove("c1", "p1", {"x": 1}, {"note": secret}, 2)
    blob = repr(proof.as_dict()) + repr(proof)
    assert secret not in blob
    for row in zk.audit_log(3):
        assert secret not in repr(row["detail"])
    # builder itself enforces the ban
    with pytest.raises(AuditKindError):
        zero_knowledge_audit_event("proved", 4, proof_id="p1", witness=secret)
    with pytest.raises(AuditKindError):
        zero_knowledge_audit_event("nope", 4, proof_id="p1")


def test_11_seq_discipline():
    zk = ZeroKnowledge()
    # rewind raises bare without consuming seq
    zk.setup("c1", 5, ceremony="transparent", constraint_digest=CONSTRAINT)
    with pytest.raises(SeqOrderError):
        zk.setup("c2", 5, ceremony="transparent", constraint_digest=CONSTRAINT)
    with pytest.raises(SeqOrderError):
        zk.setup("c2", 4, ceremony="transparent", constraint_digest=CONSTRAINT)
    # malformed seqs refused
    for bad in (True, "6", 6.0, None):
        with pytest.raises(SeqOrderError):
            zk.verify("p1", bad)
    # views validate shape but consume nothing and write no audit rows
    before = len(zk.audit_log(6))
    assert zk.circuit_ids(6) == ("c1",)
    assert zk.stats(6)["seq"] == 5
    assert zk.verify("missing", 6).valid is False
    assert len(zk.audit_log(6)) == before
    # failed mutation consumed its seq (claim-then-burn)
    with pytest.raises(UnknownProofError):
        zk.proof_record("missing", 6)
    zk.setup("c2", 7, ceremony="transparent", constraint_digest=CONSTRAINT)
    assert zk.circuit_ids(7) == ("c1", "c2")


def test_12_audit_shapes():
    zk = ZeroKnowledge()
    zk.setup("c1", 1, ceremony="transparent", constraint_digest=CONSTRAINT)
    zk.prove("c1", "p1", {"x": 1}, {"w": 2}, 2)
    zk.retire("c1", 3, reason="manual")
    log = zk.audit_log(4)
    kinds = [e["kind"] for e in log]
    assert kinds == ["setup-completed", "proved", "retired"]
    for e in log:
        assert e["schema"] == "audit.ndjson/1"
        assert e["module"] == "zero-knowledge"
        assert e["digest"].startswith("sha256:")
        for banned in ("witness", "secret", "payload", "raw", "value"):
            assert banned not in e["detail"]
    # rejected rows carry the error class, never raw material
    try:
        zk.prove("nope", "p9", {"x": 1}, {"w": 2}, 5)
    except UnknownCircuitError:
        pass
    rej = zk.audit_log(6)[-1]
    assert rej["kind"] == "zero-knowledge.rejected"
    assert rej["detail"]["error"] == "UnknownCircuitError"


def test_13_cross_instance_digest_determinism():
    def build():
        zk = ZeroKnowledge()
        s = zk.setup("c1", 1, ceremony="trusted-setup",
                     constraint_digest=CONSTRAINT,
                     participants=("alice",), toxic_waste="destroyed")
        p = zk.prove("c1", "p1", {"x": 1, "y": [1, 2]}, {"w": True}, 2)
        return s, p

    s1, p1 = build()
    s2, p2 = build()
    assert s1.digest == s2.digest
    assert s1.proving_key_digest == s2.proving_key_digest
    assert p1.digest == p2.digest
    assert p1.proof_pin == p2.proof_pin
    # different inputs -> different statement binding
    zk = ZeroKnowledge()
    zk.setup("c1", 1, ceremony="transparent", constraint_digest=CONSTRAINT)
    pa = zk.prove("c1", "pa", {"x": 1}, {"w": 2}, 2)
    pb = zk.prove("c1", "pb", {"x": 2}, {"w": 2}, 3)
    assert pa.statement_digest != pb.statement_digest
    assert pa.witness_pin == pb.witness_pin  # same witness, same pin


def test_14_views_and_stats():
    zk = ZeroKnowledge()
    zk.setup("b", 1, ceremony="transparent", constraint_digest=CONSTRAINT)
    zk.setup("a", 2, ceremony="transparent", constraint_digest=CONSTRAINT)
    assert zk.circuit_ids(3) == ("b", "a")  # insertion order
    assert zk.proof_ids(3) == ()
    assert zk.retired_ids(3) == ()
    stats = zk.stats(3)
    assert stats == {"circuits": 2, "proofs": 0, "retired": 0, "seq": 2}
    with pytest.raises(UnknownCircuitError):
        zk.setup_record("missing", 4)
    with pytest.raises(UnknownProofError):
        zk.proof_record("missing", 4)
    zk.retire("a", 5, reason="invalidated")
    assert zk.retired_ids(6) == ("a",)
    assert zk.stats(6)["retired"] == 1


def test_15_main_self_check():
    r = subprocess.run(
        [sys.executable, str(COMP / "zero_knowledge.py")],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert r.returncode == 0, r.stderr
    assert "zero-knowledge OK: setup, prove, verify, retire, refusals" in r.stdout
