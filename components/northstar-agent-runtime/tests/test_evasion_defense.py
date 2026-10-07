"""Targeted tests for evasion_defense (evasion-attack defense ledger)."""

import ast
import importlib.util
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import evasion_defense
from evasion_defense import (
    EvasionDefense,
    evasion_defense_audit_event,
    VERSION,
    SCHEMA,
    TECHNIQUES,
    ACTIONS,
    DEFENSES,
    VERDICTS,
    SUSPICIOUS_THRESHOLD,
    MALICIOUS_THRESHOLD,
    DetectionRecord,
    ResponseRecord,
    HardenRecord,
    EvasionDefenseError,
    BadIdError,
    DuplicateQueryError,
    UnknownQueryError,
    BadScoreError,
    BadTechniqueError,
    BadActionError,
    BadDefenseError,
    UnknownDetectionError,
    DuplicateResponseError,
    DuplicateModelError,
    BadDigestError,
    SeqOrderError,
    AuditKindError,
)

MODULE_PATH = Path(evasion_defense.__file__)
STDLIB_OK = {
    "__future__", "hashlib", "json", "math", "threading", "dataclasses",
    "typing", "canonical_json",
}


def load_standalone():
    """Load evasion_defense from a bare temp dir (no package context)."""
    name = "evasion_defense_standalone"
    sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location(name, str(MODULE_PATH))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def new_ed():
    return EvasionDefense()


# 1. pins
def test_version_schema_pins():
    assert VERSION == "evasion-defense.v1"
    assert SCHEMA == "northstar.evasion-defense.v1"
    assert EvasionDefense().stats()["schema"] == SCHEMA
    assert TECHNIQUES == ("fgsm", "pgd", "cw", "bim", "deepfool", "autoattack", "unrestricted")
    assert ACTIONS == ("allow", "flag", "block", "sanitize", "re-authenticate", "escalate")
    assert DEFENSES == (
        "adversarial-training", "gradient-masking", "input-sanitization",
        "certified-defense", "ensemble", "randomized-smoothing",
    )
    assert VERDICTS == ("clean", "suspicious", "malicious")
    assert SUSPICIOUS_THRESHOLD == 0.5
    assert MALICIOUS_THRESHOLD == 0.8


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


# 3. detect roundtrip + verify + verdict
def test_detect_roundtrip():
    ed = new_ed()
    rec = ed.detect("q-1", 0.92, 1, technique="pgd")
    assert rec.detection_id == "det-1"
    assert rec.query_id == "q-1"
    assert rec.technique == "pgd"
    assert rec.score_num == 920 and rec.score_den == 1000
    assert rec.score == pytest.approx(0.92)
    assert rec.verdict == "malicious"
    assert rec.verify()
    assert ed.detection_record("det-1") is rec
    assert ed.detection_ids() == ("det-1",)
    assert rec.digest.startswith("sha256:")


# 4. detect bad-input table + seq-burn + rejected rows
def test_detect_bad_inputs():
    ed = new_ed()
    seq = 0
    n_rejected = 0

    def bad(*args, **kw):
        nonlocal seq, n_rejected
        seq += 1
        with pytest.raises(EvasionDefenseError):
            ed.detect(*args, seq=seq, **kw)
        n_rejected += 1

    bad("", 0.5)                     # empty id
    bad("  ", 0.5)                   # whitespace id
    bad("q" * 129, 0.5)             # id too long
    bad(None, 0.5)                  # non-str id
    bad("q-x", 0.5, technique="nope")      # bad technique
    bad("q-x", 0.5, technique=123)         # non-str technique
    bad("q-x", 0.5, query_digest="not-a-digest")  # bad digest
    bad("q-x", 0.5, query_digest="sha256:" + "zz" * 32)  # non-hex digest
    rows = ed.audit_log()
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == n_rejected == 8
    # claim-then-burn: every failed mutation consumed its seq
    rec = ed.detect("q-x", 0.2, seq + 1)
    assert rec.verdict == "clean"


# 5. duplicate query refusal
def test_detect_duplicate_query():
    ed = new_ed()
    ed.detect("q-1", 0.1, 1)
    with pytest.raises(DuplicateQueryError):
        ed.detect("q-1", 0.9, 2)
    assert len([r for r in ed.audit_log() if r["kind"] == "rejected"]) == 1
    assert ed.stats()["detections"] == 1


# 6. score -> verdict thresholds incl. edges
def test_verdict_thresholds():
    ed = new_ed()
    cases = [
        ("e1", 0.0, "clean"),
        ("e2", 0.49, "clean"),
        ("e3", 0.5, "suspicious"),     # edge -> suspicious
        ("e4", 0.79, "suspicious"),
        ("e5", 0.8, "malicious"),      # edge -> malicious
        ("e6", 1.0, "malicious"),
        ("e7", 0, "clean"),            # int accepted
        ("e8", 1, "malicious"),
    ]
    seq = 1
    for qid, score, verdict in cases:
        rec = ed.detect(qid, score, seq)
        assert rec.verdict == verdict, (score, rec.verdict)
        seq += 1
    counts = ed.stats()["verdicts"]
    assert counts == {"clean": 3, "suspicious": 2, "malicious": 3}


# 7. score bad-input table
def test_bad_scores():
    ed = new_ed()
    seq = 0
    for i, bad_score in enumerate(
        [True, False, float("nan"), float("inf"), float("-inf"), -0.1, 1.1, "0.9", None, [0.5]]
    ):
        seq += 1
        with pytest.raises(BadScoreError):
            ed.detect(f"q-bad-{i}", bad_score, seq)


# 8. respond roundtrip + minted ids
def test_respond_roundtrip():
    ed = new_ed()
    ed.detect("q-1", 0.75, 1)
    rsp = ed.respond("det-1", "block", 2)
    assert rsp.response_id == "rsp-1"
    assert rsp.detection_id == "det-1"
    assert rsp.action == "block"
    assert rsp.reason_digest == ""
    assert rsp.verify()
    assert ed.response_record("rsp-1") is rsp
    assert ed.response_ids() == ("rsp-1",)
    # all six actions accepted
    ed2 = new_ed()
    for i, action in enumerate(ACTIONS):
        ed2.detect(f"q-{i}", 0.6, i * 2 + 1)
        r = ed2.respond(f"det-{i + 1}", action, i * 2 + 2)
        assert r.action == action and r.verify()


# 9. respond refusals
def test_respond_refusals():
    ed = new_ed()
    ed.detect("q-1", 0.9, 1)
    with pytest.raises(UnknownDetectionError):
        ed.respond("det-99", "block", 2)
    with pytest.raises(BadIdError):
        ed.respond("", "block", 3)
    with pytest.raises(BadActionError):
        ed.respond("det-1", "nuke", 4)
    with pytest.raises(BadActionError):
        ed.respond("det-1", "", 5)
    with pytest.raises(BadDigestError):
        ed.respond("det-1", "allow", 6, reason_digest="nope")
    ed.respond("det-1", "flag", 7)
    with pytest.raises(DuplicateResponseError):
        ed.respond("det-1", "block", 8)
    assert ed.stats()["responses"] == 1
    assert len([r for r in ed.audit_log() if r["kind"] == "rejected"]) == 6


# 10. harden roundtrip + all-6-defenses accepted
def test_harden_roundtrip():
    ed = new_ed()
    for i, defense in enumerate(DEFENSES):
        rec = ed.harden("m-1", defense, i + 1)
        assert rec.harden_id == f"hdn-{i + 1}"
        assert rec.model_id == "m-1"
        assert rec.defense == defense
        assert rec.verify()
    assert len(ed.defenses_for("m-1")) == 6
    rec2 = ed.harden("m-2", "ensemble", 7)
    assert rec2.model_id == "m-2"
    assert ed.stats()["models"] == 2
    assert ed.stats()["hardenings"] == 7


# 11. harden refusals
def test_harden_refusals():
    ed = new_ed()
    ed.harden("m-1", "ensemble", 1)
    with pytest.raises(DuplicateModelError):
        ed.harden("m-1", "ensemble", 2)
    with pytest.raises(BadDefenseError):
        ed.harden("m-1", "prayer", 3)
    with pytest.raises(BadDefenseError):
        ed.harden("m-1", "", 4)
    with pytest.raises(BadIdError):
        ed.harden("", "ensemble", 5)
    with pytest.raises(BadDigestError):
        ed.harden("m-2", "ensemble", 6, coverage_digest="raw-bytes")
    # same defense on a different model is fine
    r = ed.harden("m-2", "ensemble", 7)
    assert r.verify()
    assert ed.stats()["hardenings"] == 2


# 12. seq discipline
def test_seq_discipline():
    ed = new_ed()
    ed.detect("q-1", 0.1, 1)
    # rewind raises bare, consumes nothing
    with pytest.raises(SeqOrderError):
        ed.detect("q-2", 0.1, 1)
    with pytest.raises(SeqOrderError):
        ed.detect("q-2", 0.1, 0)
    assert len([r for r in ed.audit_log() if r["kind"] == "rejected"]) == 0
    # malformed seqs
    for bad_seq in (True, False, "2", 2.0, -1, None):
        with pytest.raises(SeqOrderError):
            ed.detect("q-x", 0.1, bad_seq)
    assert len([r for r in ed.audit_log() if r["kind"] == "rejected"]) == 0
    # failed mutation consumes its seq (claim-then-burn)
    with pytest.raises(BadActionError):
        ed.respond("det-1", "nope", 2)
    assert len([r for r in ed.audit_log() if r["kind"] == "rejected"]) == 1
    rsp = ed.respond("det-1", "allow", 3)
    assert rsp.response_id == "rsp-1"


# 13. audit shapes + leak ban + bad-kind
def test_audit_shapes():
    ed = new_ed()
    ed.detect("q-1", 0.95, 1, technique="cw", query_digest="sha256:" + "ab" * 32)
    ed.respond("det-1", "escalate", 2)
    ed.harden("m-1", "randomized-smoothing", 3)
    rows = ed.audit_log()
    assert [r["kind"] for r in rows] == [
        "detection-booked", "response-booked", "hardening-booked"
    ]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
    det_row = rows[0]
    assert det_row["detail"]["verdict"] == "malicious"
    assert det_row["detail"]["query_digest"] == "sha256:" + "ab" * 32
    # banned keys never cross the audit boundary
    import json as _json
    blob = _json.dumps(rows)
    for banned in ("input", "payload", "secret", "plaintext", "features", "vector"):
        assert f'"{banned}"' not in blob
    with pytest.raises(AuditKindError):
        evasion_defense_audit_event("launch-missiles")
    ev = evasion_defense_audit_event("rejected", {"seq": 9})
    assert ev["schema"] == "audit.ndjson/1"


# 14. cross-instance digest determinism + tamper breaks verify
def test_digest_determinism_and_tamper():
    a, b = new_ed(), new_ed()
    ra = a.detect("q-1", 0.66, 1, technique="fgsm")
    rb = b.detect("q-1", 0.66, 1, technique="fgsm")
    assert ra.digest == rb.digest
    rsp_a = a.respond("det-1", "sanitize", 2)
    rsp_b = b.respond("det-1", "sanitize", 2)
    assert rsp_a.digest == rsp_b.digest
    hd_a = a.harden("m", "certified-defense", 3)
    hd_b = b.harden("m", "certified-defense", 3)
    assert hd_a.digest == hd_b.digest
    # tamper evidence: corrupt a field -> verify() False
    object.__setattr__(ra, "verdict", "clean")
    assert not ra.verify()
    object.__setattr__(hd_a, "defense", "prayer")
    assert not hd_a.verify()


# 15. views read-purity + frozen-ness + concurrency + main()
def test_views_frozen_concurrency_main():
    ed = new_ed()
    ed.detect("q-1", 0.9, 1)
    ed.detect("q-2", 0.2, 2)
    ed.respond("det-1", "block", 3)
    ed.harden("m-1", "input-sanitization", 4)
    assert len(ed.verdicts_for("q-1")) == 1
    assert ed.verdicts_for("nope") == ()
    assert len(ed.defenses_for("m-1")) == 1
    before = len(ed.audit_log())
    ed.verdicts_for("q-1")
    ed.defenses_for("m-1")
    assert len(ed.audit_log()) == before  # pure reads write nothing
    stats = ed.stats()
    assert stats["queries"] == 2 and stats["detections"] == 2
    assert stats["verdicts"] == {"clean": 1, "suspicious": 0, "malicious": 1}
    # frozen records
    det = ed.detection_record("det-1")
    with pytest.raises(AttributeError):
        det.verdict = "clean"
    rsp = ed.response_record("rsp-1")
    with pytest.raises(AttributeError):
        rsp.action = "allow"
    hdn = ed.harden_record("hdn-1")
    with pytest.raises(AttributeError):
        hdn.defense = "ensemble"
    # concurrency smoke: 8 readers
    errors = []

    def read():
        try:
            for _ in range(50):
                ed.stats()
                ed.detection_record("det-1")
                ed.audit_log()
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=read) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    # main() self-check as subprocess
    proc = subprocess.run(
        [sys.executable, "-c", "import evasion_defense; evasion_defense.main()"],
        capture_output=True, text=True, timeout=60,
        cwd=str(MODULE_PATH.parent),
    )
    assert proc.returncode == 0, proc.stderr
    assert "evasion-defense OK" in proc.stdout
    # standalone import from a bare dir
    mod = load_standalone()
    assert mod.VERSION == "evasion-defense.v1"
