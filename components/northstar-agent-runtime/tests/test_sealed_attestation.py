"""Tests for the sealed-attestation in-toto envelope module, Simulated."""

import ast
import dataclasses
import subprocess
import sys
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "sealed_attestation.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("sealed_attestation", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["sealed_attestation"] = module
    spec.loader.exec_module(module)
    return module


sa = _load()


def _event():
    e = {k: f"{k}-v" for k in sa.EVENT_FIELDS}
    e["inputs_digest"] = PIN
    e["logic_digest"] = PIN
    e["execution_digest"] = PIN
    return e


def _record(seq=1):
    return sa.attest_sealed_record(
        record_hash=PIN,
        seq=seq,
        event=_event(),
        input_fingerprint=PIN,
        logic_fingerprint=PIN,
        execution_fingerprint=PIN,
        seal="de" * 32,
        prev_hash=PIN,
    )


# 1. version/schema/statement-type pins + PREDICATE_TYPES + EVENT_FIELDS
def test_pins_and_vocabularies():
    assert sa.SEALED_ATTESTATION_VERSION == "sealed-attestation.v1"
    assert sa.SCHEMA_PIN == "northstar.sealed-attestation.v1"
    assert sa.STATEMENT_TYPE == "https://in-toto.io/Statement/v1"
    assert sa.PREDICATE_TYPES == (
        "https://northstar.io/attestation/sealed-record/v1",
        "https://northstar.io/attestation/sealed-batch/v1",
        "https://northstar.io/attestation/sealed-checkpoint/v1",
    )
    assert sa.PREDICATE_SEALED_RECORD == sa.PREDICATE_TYPES[0]
    assert sa.PREDICATE_SEALED_BATCH == sa.PREDICATE_TYPES[1]
    assert sa.PREDICATE_SEALED_CHECKPOINT == sa.PREDICATE_TYPES[2]
    assert sa.EVENT_FIELDS == (
        "intent",
        "action",
        "subject",
        "authorization",
        "inputs_digest",
        "logic_digest",
        "execution_digest",
        "outcome",
    )


# 2. stdlib-only AST check
def test_stdlib_only():
    assert sa.stdlib_only() is True
    tree = ast.parse(MOD.read_text(encoding="utf-8"))
    allowed = {
        "__future__",
        "ast",
        "dataclasses",
        "hashlib",
        "json",
        "pathlib",
        "typing",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert node.module.split(".")[0] in allowed


# 3. attest_sealed_record roundtrip
def test_attest_sealed_record_roundtrip():
    att = _record(seq=1)
    assert att.subject_digest == PIN
    assert att.predicate_type == sa.PREDICATE_SEALED_RECORD
    assert att.statement_type == sa.STATEMENT_TYPE
    assert att.subject_name == "sealed-record:1"
    assert att.statement_digest.startswith("sha256:")
    assert len(att.statement_digest) == 71
    # frozen-ness
    with pytest.raises(dataclasses.FrozenInstanceError):
        att.seq = 2  # type: ignore[attr-defined]
    with pytest.raises(dataclasses.FrozenInstanceError):
        att.subject_digest = PIN2  # type: ignore[misc]
    # predicate carries the 8 fields + fingerprints + seal + prev hash
    pred = dict(att.predicate)
    assert set(pred["event"].keys()) == set(sa.EVENT_FIELDS)
    assert pred["inputFingerprint"] == PIN
    assert pred["logicFingerprint"] == PIN
    assert pred["executionFingerprint"] == PIN
    assert pred["recordSeal"] == "de" * 32
    assert pred["prevHash"] == PIN
    assert pred["seq"] == 1
    assert "merkleProof" not in pred


# 4. bad-input table for attest_sealed_record
def test_attest_sealed_record_bad_inputs():
    base = dict(
        record_hash=PIN,
        seq=1,
        event=_event(),
        input_fingerprint=PIN,
        logic_fingerprint=PIN,
        execution_fingerprint=PIN,
        seal="de" * 32,
        prev_hash=PIN,
    )

    def call(**over):
        kw = dict(base)
        kw.update(over)
        return sa.attest_sealed_record(**kw)

    with pytest.raises(sa.AttestationError):
        call(record_hash="nope")
    with pytest.raises(sa.AttestationError):
        call(record_hash="sha256:" + "zz" * 32)  # bad hex
    with pytest.raises(sa.AttestationError):
        call(seq=0)
    with pytest.raises(sa.AttestationError):
        call(seq=True)  # bool refused
    with pytest.raises(sa.AttestationError):
        call(seq="1")
    ev = _event()
    del ev["intent"]
    with pytest.raises(sa.AttestationError):
        call(event=ev)  # missing field
    ev = _event()
    ev["extra"] = "x"
    with pytest.raises(sa.AttestationError):
        call(event=ev)  # extra field
    ev = _event()
    ev["action"] = ""
    with pytest.raises(sa.AttestationError):
        call(event=ev)  # empty value
    with pytest.raises(sa.AttestationError):
        call(event="not-a-dict")
    with pytest.raises(sa.AttestationError):
        call(input_fingerprint="bad")
    with pytest.raises(sa.AttestationError):
        call(logic_fingerprint=PIN2[:-1])  # wrong length
    with pytest.raises(sa.AttestationError):
        call(execution_fingerprint=123)
    with pytest.raises(sa.AttestationError):
        call(seal="not-hex!!")
    with pytest.raises(sa.AttestationError):
        call(seal="")
    with pytest.raises(sa.AttestationError):
        call(prev_hash="sha256:short")


# 5. merkle_proof handling
def test_merkle_proof():
    proof = {"leaf_index": 3, "siblings": [PIN, PIN2], "root": PIN}
    att = sa.attest_sealed_record(
        record_hash=PIN,
        seq=4,
        event=_event(),
        input_fingerprint=PIN,
        logic_fingerprint=PIN,
        execution_fingerprint=PIN,
        seal="de" * 32,
        prev_hash=PIN,
        merkle_proof=proof,
    )
    pred = dict(att.predicate)
    assert pred["merkleProof"] == proof
    assert sa.verify_envelope(att)["envelope_ok"] is True

    bad = {"leaf_index": 3, "siblings": []}  # missing root
    with pytest.raises(sa.AttestationError):
        sa.attest_sealed_record(
            record_hash=PIN,
            seq=4,
            event=_event(),
            input_fingerprint=PIN,
            logic_fingerprint=PIN,
            execution_fingerprint=PIN,
            seal="de" * 32,
            prev_hash=PIN,
            merkle_proof=bad,
        )
    with pytest.raises(sa.AttestationError):
        sa.attest_sealed_record(
            record_hash=PIN,
            seq=4,
            event=_event(),
            input_fingerprint=PIN,
            logic_fingerprint=PIN,
            execution_fingerprint=PIN,
            seal="de" * 32,
            prev_hash=PIN,
            merkle_proof="not-a-dict",
        )
    bad_root = {"leaf_index": 0, "siblings": [], "root": "bad"}
    with pytest.raises(sa.AttestationError):
        sa.attest_sealed_record(
            record_hash=PIN,
            seq=4,
            event=_event(),
            input_fingerprint=PIN,
            logic_fingerprint=PIN,
            execution_fingerprint=PIN,
            seal="de" * 32,
            prev_hash=PIN,
            merkle_proof=bad_root,
        )


# 6. attest_sealed_batch roundtrip + bad inputs
def test_attest_sealed_batch():
    att = sa.attest_sealed_batch(
        batch_root=PIN, first_seq=1, record_count=64, batch_depth=6
    )
    assert att.subject_digest == PIN
    assert att.predicate_type == sa.PREDICATE_SEALED_BATCH
    assert att.subject_name == "sealed-batch:1-64"
    assert att.statement_digest.startswith("sha256:")
    pred = dict(att.predicate)
    assert pred["firstSeq"] == 1
    assert pred["recordCount"] == 64
    assert pred["batchDepth"] == 6
    assert pred["merkleRoot"] == PIN
    with pytest.raises(dataclasses.FrozenInstanceError):
        att.subject_name = "x"  # type: ignore[misc]

    with pytest.raises(sa.AttestationError):
        sa.attest_sealed_batch(
            batch_root="bad", first_seq=1, record_count=64, batch_depth=6
        )
    with pytest.raises(sa.AttestationError):
        sa.attest_sealed_batch(
            batch_root=PIN, first_seq=0, record_count=64, batch_depth=6
        )
    with pytest.raises(sa.AttestationError):
        sa.attest_sealed_batch(
            batch_root=PIN, first_seq=True, record_count=64, batch_depth=6
        )
    with pytest.raises(sa.AttestationError):
        sa.attest_sealed_batch(
            batch_root=PIN, first_seq=1, record_count=0, batch_depth=6
        )
    with pytest.raises(sa.AttestationError):
        sa.attest_sealed_batch(
            batch_root=PIN, first_seq=1, record_count=64, batch_depth=-1
        )
    with pytest.raises(sa.AttestationError):
        sa.attest_sealed_batch(
            batch_root=PIN, first_seq=1, record_count=64, batch_depth=False
        )


# 7. attest_checkpoint roundtrip + bad inputs
def test_attest_checkpoint():
    att = sa.attest_checkpoint(
        checkpoint_seq=64, head_hash=PIN, records_sealed=64, checkpoint_seal="de" * 32
    )
    assert att.subject_digest == PIN
    assert att.predicate_type == sa.PREDICATE_SEALED_CHECKPOINT
    assert att.subject_name == "sealed-checkpoint:64"
    assert att.statement_digest.startswith("sha256:")
    pred = dict(att.predicate)
    assert pred["checkpointSeq"] == 64
    assert pred["headHash"] == PIN
    assert pred["recordsSealed"] == 64
    assert pred["checkpointSeal"] == "de" * 32

    with pytest.raises(sa.AttestationError):
        sa.attest_checkpoint(
            checkpoint_seq=0, head_hash=PIN, records_sealed=64, checkpoint_seal="de" * 32
        )
    with pytest.raises(sa.AttestationError):
        sa.attest_checkpoint(
            checkpoint_seq=64, head_hash="bad", records_sealed=64, checkpoint_seal="de" * 32
        )
    with pytest.raises(sa.AttestationError):
        sa.attest_checkpoint(
            checkpoint_seq=64, head_hash=PIN, records_sealed=0, checkpoint_seal="de" * 32
        )
    with pytest.raises(sa.AttestationError):
        sa.attest_checkpoint(
            checkpoint_seq=64, head_hash=PIN, records_sealed=64, checkpoint_seal=""
        )


# 8. verify_envelope: all three kinds
def test_verify_envelope_all_kinds():
    rec = _record(seq=1)
    batch = sa.attest_sealed_batch(
        batch_root=PIN, first_seq=1, record_count=64, batch_depth=6
    )
    cp = sa.attest_checkpoint(
        checkpoint_seq=64, head_hash=PIN, records_sealed=64, checkpoint_seal="de" * 32
    )
    for att, ptype in (
        (rec, sa.PREDICATE_SEALED_RECORD),
        (batch, sa.PREDICATE_SEALED_BATCH),
        (cp, sa.PREDICATE_SEALED_CHECKPOINT),
    ):
        report = sa.verify_envelope(att)
        assert report["envelope_ok"] is True
        assert report["signed"] is False
        assert report["predicate_type"] == ptype
        assert report["version"] == sa.SEALED_ATTESTATION_VERSION


# 9. verify_envelope tamper detection
def test_verify_envelope_tamper():
    att = _record(seq=1)
    # Tamper with the predicate via dataclasses.replace.
    pred = dict(att.predicate)
    pred["seq"] = 999
    tampered = dataclasses.replace(
        att, predicate=tuple(sorted(pred.items()))
    )
    with pytest.raises(sa.AttestationError):
        sa.verify_envelope(tampered)
    # Wrong statement digest.
    tampered2 = dataclasses.replace(att, statement_digest=PIN2)
    with pytest.raises(sa.AttestationError):
        sa.verify_envelope(tampered2)
    # Tampered subject digest.
    tampered3 = dataclasses.replace(att, subject_digest=PIN2)
    with pytest.raises(sa.AttestationError):
        sa.verify_envelope(tampered3)


# 10. verify_envelope rejects unknown predicate_type / statement_type
def test_verify_envelope_rejects_unknown_types():
    att = _record(seq=1)
    bad_pred = dataclasses.replace(
        att, predicate_type="https://example.com/evil/v1"
    )
    with pytest.raises(sa.AttestationError):
        sa.verify_envelope(bad_pred)
    bad_stype = dataclasses.replace(
        att, statement_type="https://example.com/Statement/v9"
    )
    with pytest.raises(sa.AttestationError):
        sa.verify_envelope(bad_stype)


# 11. verify_envelope rejects non-Attestation input
def test_verify_envelope_rejects_non_attestation():
    for bad in (None, "x", 42, {"_type": "x"}, ["attestation"]):
        with pytest.raises(sa.AttestationError):
            sa.verify_envelope(bad)


# 12. to_dict shape
def test_to_dict_shape():
    att = _record(seq=7)
    d = att.to_dict()
    assert d["_type"] == sa.STATEMENT_TYPE
    assert isinstance(d["subject"], list) and len(d["subject"]) == 1
    subj = d["subject"][0]
    assert subj["name"] == "sealed-record:7"
    # digest.sha256 carries the hex WITHOUT the sha256: prefix
    assert subj["digest"] == {"sha256": PIN[7:]}
    assert not subj["digest"]["sha256"].startswith("sha256:")
    assert d["predicateType"] == sa.PREDICATE_SEALED_RECORD
    pred = d["predicate"]
    assert set(pred["event"].keys()) == set(sa.EVENT_FIELDS)
    assert pred["inputFingerprint"] == PIN
    assert pred["recordSeal"] == "de" * 32
    # round-trip: to_dict output re-hashes to the statement digest
    import hashlib
    import json

    canon = json.dumps(d, sort_keys=True, separators=(",", ":")).encode()
    assert "sha256:" + hashlib.sha256(canon).hexdigest() == att.statement_digest


# 13. determinism
def test_determinism():
    a1 = _record(seq=1)
    a2 = _record(seq=1)
    assert a1.statement_digest == a2.statement_digest
    assert a1 == a2
    a3 = _record(seq=2)
    assert a3.statement_digest != a1.statement_digest
    # different content -> different digest
    ev = _event()
    ev["outcome"] = "different"
    a4 = sa.attest_sealed_record(
        record_hash=PIN,
        seq=1,
        event=ev,
        input_fingerprint=PIN,
        logic_fingerprint=PIN,
        execution_fingerprint=PIN,
        seal="de" * 32,
        prev_hash=PIN,
    )
    assert a4.statement_digest != a1.statement_digest


# 14. Attestation frozen-ness
def test_attestation_frozen():
    att = _record(seq=1)
    for field in (
        "statement_type",
        "subject_name",
        "subject_digest",
        "predicate_type",
        "predicate",
        "statement_digest",
    ):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(att, field, "x")


# 15. main() subprocess self-check
def test_main_subprocess():
    result = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "OK" in result.stdout
