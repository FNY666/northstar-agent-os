"""Tests for threat_hunting.py: hypothesis / hunt / validate bookkeeping."""

import ast
import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

import threat_hunting as th

HERE = Path(__file__).resolve().parent
MODULE = Path(__file__).resolve().parent.parent / "threat_hunting.py"


def digest(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def make_hunt(ledger=None, hunt_id="HUNT-001", seq=1, **kwargs):
    ledger = ledger or th.ThreatHunting()
    ledger.hypothesize(hunt_id, seq, **kwargs)
    return ledger


def test_version_and_schema_pins():
    assert th.THREAT_HUNTING_VERSION == "threat-hunting.v1"
    assert th.THREAT_HUNTING_SCHEMA == "northstar.threat-hunting.v1"


def test_stdlib_only():
    tree = ast.parse(MODULE.read_text())
    allowed = {
        "hashlib",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "canonical_json",
        "json",
        "sys",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_hypothesize_roundtrip_and_verify():
    ledger = make_hunt(hypothesis_class="data-staging", rationale_digest=digest("r1"))
    record = ledger.hypothesis_record("HUNT-001", 2)
    assert record.hypothesis_class == "data-staging"
    assert record.rationale_digest == digest("r1")
    assert record.verify()
    assert record.as_dict()["schema"] == "northstar.threat-hunting.v1"
    assert ledger.hunt_ids(3) == ("HUNT-001",)


def test_hypothesize_duplicate_and_bad_inputs_consume_seq():
    ledger = make_hunt()
    with pytest.raises(th.DuplicateHuntError):
        ledger.hypothesize("HUNT-001", 2)
    rejected = [e for e in ledger.audit_log(3) if e["kind"] == th.KIND_REJECTED]
    assert len(rejected) == 1
    for bad_seq in (True, "x", -1):
        with pytest.raises(th.SeqOrderError):
            ledger.hypothesize("BAD", bad_seq)
    with pytest.raises(th.BadHuntError):
        ledger.hypothesize("  ", 3)
    assert ledger.stats(4)["hypotheses"] == 1


def test_hypothesis_vocabulary_accepted():
    ledger = th.ThreatHunting()
    for i, cls in enumerate(sorted(th._HYPOTHESES)):
        ledger.hypothesize(f"H-{i}", i + 1, hypothesis_class=cls)
        assert ledger.hypothesis_record(f"H-{i}", i + 1).hypothesis_class == cls
    assert ledger.stats(20)["hypotheses"] == 8
    with pytest.raises(th.BadHypothesisError):
        ledger.hypothesize("H-BAD", 21, hypothesis_class="alien-landing")


def test_hunt_roundtrip_verify_and_minted_ids():
    ledger = make_hunt()
    r1 = ledger.hunt("HUNT-001", 2, scope="endpoint", outcome="no-evidence")
    r2 = ledger.hunt(
        "HUNT-001", 3, scope="network", data_digest=digest("d"), outcome="suspicious"
    )
    assert r1.hunt_run_id != r2.hunt_run_id
    assert r1.hunt_run_id.startswith("hnt-")
    assert r1.verify() and r2.verify()
    runs = ledger.hunt_runs("HUNT-001", 4)
    assert [r.outcome for r in runs] == ["no-evidence", "suspicious"]
    status = ledger.status("HUNT-001", 5)
    assert status.hunt_run_count == 2 and not status.validated


def test_hunt_without_hypothesis_refused():
    ledger = th.ThreatHunting()
    with pytest.raises(th.UnknownHuntError):
        ledger.hunt("NOPE", 1)
    with pytest.raises(th.UnknownHuntError):
        ledger.validate("NOPE", 2)
    rejected = [e for e in ledger.audit_log(3) if e["kind"] == th.KIND_REJECTED]
    assert len(rejected) == 2


def test_hunt_bad_inputs_consume_seq():
    ledger = make_hunt()
    with pytest.raises(th.BadScopeError):
        ledger.hunt("HUNT-001", 2, scope="telegram")
    with pytest.raises(th.BadOutcomeError):
        ledger.hunt("HUNT-001", 3, outcome="probably-guilty")
    with pytest.raises(th.BadDigestError):
        ledger.hunt("HUNT-001", 4, data_digest="not-a-pin")
    with pytest.raises(th.BadDigestError):
        ledger.hunt("HUNT-001", 5, evidence_digest=b"bytes")  # type: ignore
    rejected = [e for e in ledger.audit_log(6) if e["kind"] == th.KIND_REJECTED]
    assert len(rejected) == 4
    assert ledger.stats(7)["hunt_runs"] == 0


def test_validate_roundtrip_verdicts_and_terminality():
    ledger = make_hunt()
    ledger.hunt("HUNT-001", 2, outcome="confirmed")
    v = ledger.validate("HUNT-001", 3, verdict="threat-confirmed")
    assert v.validation_id.startswith("val-")
    assert v.verify()
    assert ledger.validation_record("HUNT-001", 4).verdict == "threat-confirmed"
    status = ledger.status("HUNT-001", 5)
    assert status.validated and status.verdict == "threat-confirmed"
    with pytest.raises(th.ValidatedHuntError):
        ledger.validate("HUNT-001", 6, verdict="benign")
    with pytest.raises(th.ValidatedHuntError):
        ledger.hunt("HUNT-001", 7)
    rejected = [e for e in ledger.audit_log(8) if e["kind"] == th.KIND_REJECTED]
    assert len(rejected) == 2


def test_validate_bad_verdict_consume_seq():
    ledger = make_hunt()
    with pytest.raises(th.BadVerdictError):
        ledger.validate("HUNT-001", 2, verdict="kinda-bad")
    rejected = [e for e in ledger.audit_log(3) if e["kind"] == th.KIND_REJECTED]
    assert len(rejected) == 1
    v = ledger.validate("HUNT-001", 4, verdict="false-positive")
    assert v.verdict == "false-positive"


def test_all_verdicts_and_scopes_accepted():
    ledger = th.ThreatHunting()
    seq = 1
    for i, verdict in enumerate(sorted(th._VERDICTS)):
        hid = f"V-{i}"
        ledger.hypothesize(hid, seq); seq += 1
        ledger.validate(hid, seq, verdict=verdict); seq += 1
        assert ledger.validation_record(hid, seq - 1).verdict == verdict
    ledger2 = make_hunt(hunt_id="S-001", seq=1)
    for i, scope in enumerate(sorted(th._SCOPES)):
        r = ledger2.hunt("S-001", 2 + i, scope=scope)
        assert r.scope == scope
    ledger3 = make_hunt(hunt_id="O-001", seq=1)
    for i, outcome in enumerate(sorted(th._OUTCOMES)):
        r = ledger3.hunt("O-001", 2 + i, outcome=outcome)
        assert r.outcome == outcome


def test_seq_discipline_rewind_bare_and_views():
    ledger = make_hunt()
    ledger.hunt("HUNT-001", 2)
    with pytest.raises(th.SeqOrderError):
        ledger.hypothesize("H-2", 2)  # rewind raises bare
    with pytest.raises(th.SeqOrderError):
        ledger.hunt("HUNT-001", 1)
    rejected = [e for e in ledger.audit_log(3) if e["kind"] == th.KIND_REJECTED]
    assert len(rejected) == 0  # rewinds consume nothing, book nothing
    before = len(ledger.audit_log(3))
    ledger.status("HUNT-001", 3)  # same-seq reads allowed
    ledger.hunt_ids(3)
    assert len(ledger.audit_log(3)) == before  # pure reads book nothing
    with pytest.raises(th.UnknownHuntError):
        ledger.hunt_runs("MISSING", 4)


def test_audit_shapes_and_leak_ban():
    ledger = make_hunt(rationale_digest=digest("why"))
    ledger.hunt("HUNT-001", 2, scope="identity", outcome="inconclusive")
    ledger.validate("HUNT-001", 3, verdict="needs-more-data")
    kinds = [e["kind"] for e in ledger.audit_log(4)]
    assert kinds == [
        th.KIND_HYPOTHESIZED,
        th.KIND_HUNTED,
        th.KIND_VALIDATED,
    ]
    for e in ledger.audit_log(4):
        assert e["schema"] == "audit.ndjson/1"
    import json

    blob = json.dumps([e for e in ledger.audit_log(4)])
    for banned in ("why", "c2-beaconing".replace("-", ""), "secret"):
        assert banned not in blob
    for banned_key in th._BANNED_AUDIT_KEYS:
        with pytest.raises(th.AuditKindError):
            th.threat_hunting_audit_event(
                th.KIND_HUNTED, 5, **{banned_key: "raw"}
            )
    with pytest.raises(th.AuditKindError):
        th.threat_hunting_audit_event("bogus-kind", 5)


def test_records_frozen_and_tamper_rejected():
    ledger = make_hunt()
    record = ledger.hypothesis_record("HUNT-001", 2)
    with pytest.raises(Exception):
        record.hypothesis_class = "x"  # frozen
    other = th.ThreatHunting()
    other.hypothesize("HUNT-001", 1)
    other_rec = other.hypothesis_record("HUNT-001", 2)
    assert other_rec.digest == record.digest  # cross-instance determinism
    tampered = record.__class__(
        hunt_id=record.hunt_id,
        hypothesis_class="persistence",
        rationale_digest=record.rationale_digest,
        seq=record.seq,
        digest=record.digest,
    )
    assert not tampered.verify()


def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MODULE)],
        capture_output=True,
        text=True,
        cwd=str(HERE.parent),
    )
    assert proc.returncode == 0, proc.stderr
    assert "threat-hunting OK" in proc.stdout
