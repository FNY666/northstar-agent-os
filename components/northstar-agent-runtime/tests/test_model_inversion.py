"""Targeted tests for model_inversion (inversion-attack defense ledger)."""

import ast
import hashlib
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import model_inversion
from model_inversion import (
    ModelInversion,
    model_inversion_audit_event,
    VERSION,
    SCHEMA,
    RISK_CLASSES,
    VERDICTS,
    DEFENSES,
    STRENGTHS,
    CONFIRMED_SIMILARITY,
    SUSPECTED_SIMILARITY,
    SUSPECTED_QUERIES,
    ModelRecord,
    DetectionRecord,
    DefenseRecord,
    AuditReport,
    ModelInversionError,
    BadModelError,
    DuplicateModelError,
    UnknownModelError,
    BadRiskClassError,
    BadSignalError,
    BadDefenseError,
    BadStrengthError,
    BadDigestError,
    SeqOrderError,
    AuditKindError,
)

MODULE_PATH = Path(model_inversion.__file__)
STDLIB_OK = {
    "__future__", "hashlib", "json", "math", "threading", "dataclasses",
    "typing", "canonical_json",
}

PIN = "sha256:" + "ab" * 32


def new_mi():
    mi = ModelInversion()
    mi.register_model("m1", 1, risk_class="high")
    return mi


# 1. pins
def test_version_schema_pins():
    assert VERSION == "model-inversion.v1"
    assert SCHEMA == "northstar.model-inversion.v1"
    assert ModelInversion().stats()["schema"] == SCHEMA
    assert RISK_CLASSES == ("low", "medium", "high", "critical")
    assert VERDICTS == ("confirmed", "suspected", "benign")
    assert len(DEFENSES) == 7 and "confidence-truncation" in DEFENSES
    assert STRENGTHS == ("light", "standard", "strict")
    assert CONFIRMED_SIMILARITY == 0.8
    assert SUSPECTED_SIMILARITY == 0.5
    assert SUSPECTED_QUERIES == 200


# 2. stdlib only
def test_stdlib_only():
    tree = ast.parse(MODULE_PATH.read_text())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    assert imports <= STDLIB_OK, imports - STDLIB_OK


# 3. register roundtrip + verify + tamper
def test_register_roundtrip_and_verify():
    mi = ModelInversion()
    rec = mi.register_model("face-clf", 1, risk_class="critical", owner_digest=PIN)
    assert isinstance(rec, ModelRecord)
    assert rec.model_id == "face-clf" and rec.risk_class == "critical"
    assert rec.owner_digest == PIN and rec.verify()
    assert mi.model_record("face-clf") is rec
    assert mi.model_ids() == ("face-clf",)
    # tamper breaks verify
    object.__setattr__(rec, "risk_class", "low")
    assert not rec.verify()


# 4. register bad inputs + duplicate + seq-burn + rejected rows
def test_register_bad_inputs():
    mi = ModelInversion()
    mi.register_model("ok", 1)
    bad = [
        (("ok",), {}, DuplicateModelError),                    # duplicate
        (("",), {}, BadModelError),                            # empty id
        (("  ",), {}, BadModelError),                          # whitespace id
        ((None,), {}, BadModelError),                          # non-str id
        (("x",), {"risk_class": "extreme"}, BadRiskClassError),  # bad risk class
        (("x",), {"owner_digest": "not-a-digest"}, BadDigestError),  # bad digest
        (("x",), {"owner_digest": 123}, BadDigestError),       # non-str digest
    ]
    n_rejected = 0
    seq = 2
    for args, kwargs, exc in bad:
        with pytest.raises(exc):
            mi.register_model(*args, seq, **kwargs)
        seq += 1
        n_rejected += 1
    rejected = [r for r in mi.audit_log() if r["kind"] == "rejected"]
    assert len(rejected) == n_rejected
    assert all(r["detail"]["op"] == "register_model" for r in rejected)
    assert len(mi.audit_log()) == 1 + n_rejected  # 1 model-registered


# 5. detect roundtrip + verify + minted ids
def test_detect_roundtrip_and_verify():
    mi = new_mi()
    rec = mi.detect("m1", 2, signals_digest=PIN, queries=10, similarity=0.9, entropy=0.05)
    assert isinstance(rec, DetectionRecord)
    assert rec.detection_id == "det-1"
    assert rec.verdict == "confirmed"
    assert rec.queries == 10 and rec.similarity == 0.9 and rec.entropy == 0.05
    assert rec.verify()
    assert mi.detection_record("det-1") is rec
    assert mi.detections_for("m1") == ("det-1",)
    rec2 = mi.detect("m1", 3)
    assert rec2.detection_id == "det-2" and rec2.verdict == "benign"
    # tamper breaks verify
    object.__setattr__(rec, "similarity", 0.0)
    assert not rec.verify()


# 6. detect verdict thresholds incl. boundary edges
def test_detect_verdict_thresholds():
    mi = new_mi()
    cases = [
        (dict(similarity=1.0, queries=0), "confirmed"),
        (dict(similarity=0.8, queries=0), "confirmed"),      # edge
        (dict(similarity=0.7999, queries=0), "suspected"),
        (dict(similarity=0.5, queries=0), "suspected"),      # edge
        (dict(similarity=0.4999, queries=199), "benign"),
        (dict(similarity=0.4999, queries=200), "suspected"), # query edge
        (dict(similarity=0.0, queries=1000), "suspected"),
        (dict(similarity=0.0, queries=0), "benign"),
        (dict(similarity=0, queries=0), "benign"),          # int accepted
    ]
    seq = 2
    for kwargs, want in cases:
        rec = mi.detect("m1", seq, **kwargs)
        assert rec.verdict == want, (kwargs, rec.verdict)
        seq += 1


# 7. detect bad inputs + seq-burn + rejected rows
def test_detect_bad_inputs():
    mi = new_mi()
    bad = [
        (dict(similarity=True), BadSignalError),             # bool similarity
        (dict(similarity=float("nan")), BadSignalError),     # nan
        (dict(similarity=float("inf")), BadSignalError),     # inf
        (dict(similarity=1.5), BadSignalError),              # out of range
        (dict(similarity=-0.1), BadSignalError),             # negative
        (dict(queries=-1), BadSignalError),                  # negative count
        (dict(queries=True), BadSignalError),                # bool count
        (dict(queries=1.5), BadSignalError),                 # non-int count
        (dict(entropy=float("nan")), BadSignalError),        # nan entropy
        (dict(entropy=-1.0), BadSignalError),                # negative entropy
        (dict(signals_digest="raw-text"), BadDigestError),   # raw digest
    ]
    seq = 2
    for kwargs, exc in bad:
        with pytest.raises(exc):
            mi.detect("m1", seq, **kwargs)
        seq += 1
    with pytest.raises(UnknownModelError):                   # unknown model
        mi.detect("ghost", seq)
    rejected = [r for r in mi.audit_log() if r["kind"] == "rejected"]
    assert len(rejected) == len(bad) + 1
    assert all(r["detail"]["op"] == "detect" for r in rejected)
    assert mi.detections_for("m1") == ()                     # nothing booked


# 8. defend roundtrip + full defense vocabulary
def test_defend_roundtrip_and_vocabulary():
    mi = new_mi()
    seen = []
    seq = 2
    for defense in DEFENSES:
        rec = mi.defend("m1", seq, defense, strength="strict", detail_digest=PIN)
        assert isinstance(rec, DefenseRecord)
        assert rec.defense == defense and rec.strength == "strict"
        assert rec.verify()
        seen.append(rec.defense_id)
        seq += 1
    assert seen == [f"def-{i}" for i in range(1, 8)]
    assert mi.defenses_for("m1") == tuple(seen)
    assert mi.defense_record("def-3").defense == DEFENSES[2]


# 9. defend bad inputs + seq-burn + rejected rows
def test_defend_bad_inputs():
    mi = new_mi()
    bad = [
        (("delete-everything",), {}, BadDefenseError),
        (("",), {}, BadDefenseError),
        ((None,), {}, BadDefenseError),
        (("block",), {"strength": "maximum"}, BadStrengthError),
        (("block",), {"detail_digest": "raw"}, BadDigestError),
    ]
    seq = 2
    for args, kwargs, exc in bad:
        with pytest.raises(exc):
            mi.defend("m1", seq, *args, **kwargs)
        seq += 1
    with pytest.raises(UnknownModelError):
        mi.defend("ghost", seq, "block")
    rejected = [r for r in mi.audit_log() if r["kind"] == "rejected"]
    assert len(rejected) == len(bad) + 1
    assert all(r["detail"]["op"] == "defend" for r in rejected)


# 10. audit report math + verify + tamper
def test_audit_report_math_and_verify():
    mi = new_mi()
    mi.register_model("m2", 2, risk_class="low")
    mi.detect("m1", 3, similarity=0.9)              # confirmed
    mi.detect("m1", 4, similarity=0.6)              # suspected
    mi.detect("m1", 5, similarity=0.1)              # benign
    mi.detect("m2", 6, similarity=0.95)             # confirmed, other model
    mi.defend("m1", 7, "block")
    mi.defend("m1", 8, "block")
    mi.defend("m1", 9, "rate-limit")
    rep = mi.audit(10, "m1")
    assert isinstance(rep, AuditReport)
    assert rep.model_id == "m1"
    assert rep.detections == 3
    assert dict(rep.verdict_counts) == {
        "confirmed": 1, "suspected": 1, "benign": 1
    }
    assert rep.defenses == 3
    assert dict(rep.defense_counts)["block"] == 2
    assert dict(rep.defense_counts)["rate-limit"] == 1
    assert rep.verify()
    # all-model aggregation
    rep_all = mi.audit(11)
    assert rep_all.model_id == "" and rep_all.detections == 4
    assert dict(rep_all.verdict_counts)["confirmed"] == 2
    # tamper breaks verify
    object.__setattr__(rep, "detections", 99)
    assert not rep.verify()
    # unknown model refuses without side effects
    with pytest.raises(UnknownModelError):
        mi.audit(12, "ghost")


# 11. audit read-purity: same seq twice, no rows, no consumption
def test_audit_read_purity():
    mi = new_mi()
    mi.detect("m1", 2, similarity=0.9)
    before = len(mi.audit_log())
    r1 = mi.audit(3, "m1")
    r2 = mi.audit(3, "m1")          # same seq re-usable
    assert r1.digest == r2.digest
    assert len(mi.audit_log()) == before  # no audit rows written
    # seq not consumed: a later mutation may reuse any higher seq
    mi.defend("m1", 3, "block")     # seq 3 still free for mutations
    assert mi.defenses_for("m1") == ("def-1",)


# 12. seq discipline: rewind bare, malformed seqs
def test_seq_discipline():
    mi = new_mi()                    # last_seq == 1
    with pytest.raises(SeqOrderError):
        mi.detect("m1", 1, similarity=0.1)   # rewind: bare raise
    with pytest.raises(SeqOrderError):
        mi.detect("m1", 0, similarity=0.1)   # below current: bare raise
    # no rejected rows for bare rewinds, no seq consumption
    assert not [r for r in mi.audit_log() if r["kind"] == "rejected"]
    mi.detect("m1", 2, similarity=0.1)        # seq 2 still usable
    for bad_seq in (True, -1, 1.5, "2", None):
        with pytest.raises(SeqOrderError):
            mi.audit(bad_seq, "m1")           # views validate shape too


# 13. audit event shapes + leak ban + bad kind
def test_audit_shapes_and_leak_ban():
    ev = model_inversion_audit_event("detection-booked", {"detection_id": "det-1"})
    assert ev["kind"] == "detection-booked"
    assert ev["schema"] == "audit.ndjson/1"
    assert ev["detail"] == {"detection_id": "det-1"}
    with pytest.raises(AuditKindError):
        model_inversion_audit_event("nonsense")
    # raw reconstruction data banned from the audit boundary
    for banned in (
        "sample", "reconstruction", "image", "pixels", "training_data",
        "embedding", "query", "text", "secret", "face", "biometric",
    ):
        with pytest.raises(BadDigestError):
            model_inversion_audit_event("detection-booked", {banned: "x"})


# 14. cross-instance determinism + frozen-ness + concurrency smoke
def test_determinism_frozen_concurrency():
    a, b = ModelInversion(), ModelInversion()
    ra = a.register_model("m", 1, risk_class="medium", owner_digest=PIN)
    rb = b.register_model("m", 1, risk_class="medium", owner_digest=PIN)
    assert ra.digest == rb.digest
    da = a.detect("m", 2, signals_digest=PIN, queries=7, similarity=0.75, entropy=1.2)
    db = b.detect("m", 2, signals_digest=PIN, queries=7, similarity=0.75, entropy=1.2)
    assert da.digest == db.digest and da.verdict == "suspected"
    for rec in (ra, da):
        with pytest.raises(Exception):
            rec.model_id = "x"     # frozen
    # read smoke across threads
    errs = []
    def reader():
        try:
            for _ in range(50):
                a.model_ids()
                a.detections_for("m")
                a.audit(3, "m")
        except Exception as e:  # pragma: no cover
            errs.append(e)
    threads = [threading.Thread(target=reader) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errs


# 15. main() self-check via subprocess
def test_main_subprocess():
    out = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True, text=True, timeout=30,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == (
        "model-inversion OK: register, detect, defend, audit, pins"
    )
