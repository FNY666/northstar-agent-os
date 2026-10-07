"""Tests for critique_model (critique-model decision ledger, Simulated)."""

import ast
import hashlib
import subprocess
import sys
import threading

import pytest

from critique_model import (
    CRITIQUE_MODEL_VERSION,
    SCHEMA_PIN,
    CRITIQUE_DIMENSIONS,
    CRITIQUE_VERDICTS,
    IMPROVE_STRATEGIES,
    AUDIT_KINDS,
    CritiqueModelError,
    BadIdError,
    BadDigestError,
    BadDimensionError,
    BadVerdictError,
    BadStrategyError,
    BadReasonError,
    SeqOrderError,
    DuplicateDraftError,
    UnknownDraftError,
    UnknownCritiqueError,
    NoCritiqueError,
    RetiredDraftError,
    AuditKindError,
    DraftRecord,
    CritiqueRecord,
    ImprovementRecord,
    CritiqueReport,
    RetireRecord,
    CritiqueModel,
    critique_model_audit_event,
)

STDLIB_ALLOW = {
    "hashlib", "json", "threading", "dataclasses", "typing", "__future__",
    "canonical_json", "ast",
}


def _digest(tag: bytes = b"draft") -> str:
    return "sha256:" + hashlib.sha256(tag).hexdigest()


def _cm() -> CritiqueModel:
    return CritiqueModel()


# 1. version/schema/vocabulary pins
def test_pins():
    assert CRITIQUE_MODEL_VERSION == "critique-model.v1"
    assert SCHEMA_PIN == "northstar.critique-model.v1"
    assert CRITIQUE_DIMENSIONS == (
        "helpfulness", "honesty", "harmlessness", "coherence",
        "factuality", "conciseness", "completeness", "tone",
    )
    assert CRITIQUE_VERDICTS == (
        "approved", "needs-revision", "rejected", "escalated",
    )
    assert IMPROVE_STRATEGIES == (
        "rewrite", "augment", "trim", "reframe",
        "fact-check", "tone-shift", "escalate-human", "abstain",
    )
    assert AUDIT_KINDS == (
        "submitted", "critiqued", "improved", "retired", "rejected",
    )


# 2. stdlib-only AST check
def test_stdlib_only():
    import critique_model as mod
    tree = ast.parse(open(mod.__file__).read())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= STDLIB_ALLOW, imports - STDLIB_ALLOW
    assert mod.stdlib_only()


# 3. submit roundtrip + verify + frozen-ness
def test_submit_roundtrip():
    cm = _cm()
    rec = cm.submit("d-1", 1, draft_digest=_digest(), author_digest=_digest(b"a"))
    assert rec.draft_id == "d-1"
    assert rec.verify()
    assert rec.as_dict()["schema"] == SCHEMA_PIN
    with pytest.raises(Exception):
        rec.draft_id = "d-2"  # frozen


# 4. submit bad-input table + duplicate + retired + seq-burn
def test_submit_bad_inputs():
    cm = _cm()
    seq = 0
    bad = [
        (lambda s: cm.submit("", s), BadIdError),
        (lambda s: cm.submit(123, s), BadIdError),
        (lambda s: cm.submit("d-1", s, draft_digest="raw"), BadDigestError),
        (lambda s: cm.submit("d-1", s, draft_digest="md5:abc"), BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    seq += 1
    cm.submit("d-1", seq)
    seq += 1
    with pytest.raises(DuplicateDraftError):
        cm.submit("d-1", seq)
    rows = cm.audit_log(seq + 1)
    rejected = [r for r in rows if r["kind"] == "critique-model.rejected"]
    assert len(rejected) == 5  # 4 bad-input + 1 duplicate, all burned
    seq += 1
    cm.retire("d-1", seq)
    seq += 1
    with pytest.raises(RetiredDraftError):
        cm.submit("d-1", seq)


# 5. critique roundtrip + minted ids + unknown-draft refusal
def test_critique_roundtrip():
    cm = _cm()
    cm.submit("d-1", 1)
    c1 = cm.critique("d-1", 2, dimension="honesty", verdict="approved")
    c2 = cm.critique("d-1", 3, dimension="factuality", verdict="rejected")
    assert c1.critique_id == "crt-1"
    assert c2.critique_id == "crt-2"
    assert c1.verify() and c2.verify()
    assert cm.critiques_for("d-1", 4) == ("crt-1", "crt-2")
    with pytest.raises(UnknownDraftError):
        cm.critique("ghost", 5)


# 6. critique bad-input table + seq-burn
def test_critique_bad_inputs():
    cm = _cm()
    cm.submit("d-1", 1)
    seq = 1
    bad = [
        (lambda s: cm.critique("", s), BadIdError),
        (lambda s: cm.critique("d-1", s, dimension="vibes"), BadDimensionError),
        (lambda s: cm.critique("d-1", s, verdict="meh"), BadVerdictError),
        (lambda s: cm.critique("d-1", s, evidence_digest="raw"), BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    rows = cm.audit_log(seq + 1)
    rejected = [r for r in rows if r["kind"] == "critique-model.rejected"]
    assert len(rejected) == 4


# 7. full 8-dimension vocabulary acceptance
def test_full_dimension_vocabulary():
    cm = _cm()
    cm.submit("d-1", 1)
    for i, dim in enumerate(CRITIQUE_DIMENSIONS):
        rec = cm.critique("d-1", i + 2, dimension=dim, verdict="approved")
        assert rec.dimension == dim
    assert len(cm.critiques_for("d-1", 100)) == 8


# 8. improve roundtrip + chain + no-critique refusal
def test_improve_roundtrip_and_chain():
    cm = _cm()
    cm.submit("d-1", 1)
    with pytest.raises(NoCritiqueError):
        cm.improve("d-1", 2)
    cm.critique("d-1", 3, verdict="needs-revision")
    i1 = cm.improve("d-1", 4, strategy="rewrite")
    i2 = cm.improve("d-1", 5, strategy="fact-check")
    assert i1.improvement_id == "imp-1"
    assert i2.improvement_id == "imp-2"
    assert i1.basis == ("crt-1",) and i2.basis == ("crt-1",)
    assert i1.verify() and i2.verify()
    assert cm.improvements_for("d-1", 6) == ("imp-1", "imp-2")
    seq = 7
    for bad_strategy in ("vibes", "", 123):
        with pytest.raises(BadStrategyError):
            cm.improve("d-1", seq, strategy=bad_strategy)
        seq += 1


# 9. verify posture math (all 5 postures + precedence + unknown refusal)
def test_verify_posture_math():
    cm = _cm()
    cm.submit("d-1", 1)
    assert cm.verify("d-1", 2).posture == "uncritiqued"
    cm.critique("d-1", 3, verdict="approved")
    assert cm.verify("d-1", 4).posture == "approved"
    cm.critique("d-1", 5, verdict="needs-revision")
    assert cm.verify("d-1", 6).posture == "needs-revision"
    cm.critique("d-1", 7, verdict="escalated")
    assert cm.verify("d-1", 8).posture == "escalated"
    cm.critique("d-1", 9, verdict="rejected")
    assert cm.verify("d-1", 10).posture == "rejected"
    with pytest.raises(UnknownDraftError):
        cm.verify("ghost", 11)


# 10. verify read purity + tamper-as-data
def test_verify_read_purity_and_tamper():
    cm = _cm()
    cm.submit("d-1", 1)
    cm.critique("d-1", 2, verdict="approved")
    n_audit = len(cm.audit_log(3))
    r1 = cm.verify("d-1", 3)
    r2 = cm.verify("d-1", 3)  # same seq reuse is fine on reads
    assert r1.verify() and r2.verify()
    assert len(cm.audit_log(3)) == n_audit  # reads add no rows
    crit = cm.critique_record("crt-1", 3)
    object.__setattr__(crit, "verdict", "rejected")
    assert cm.verify("d-1", 3).integrity_ok is False  # tamper as data
    assert cm.verify("d-1", 3).posture == "rejected"  # derived from tampered read


# 11. retire terminality + id non-recycling + post-retire refusals
def test_retire_terminality():
    cm = _cm()
    cm.submit("d-1", 1)
    cm.critique("d-1", 2, verdict="approved")
    cm.retire("d-1", 3, reason="review-complete")
    assert cm.retired_ids(4) == ("d-1",)
    seq = 5
    for op in (
        lambda s: cm.submit("d-1", s),
        lambda s: cm.critique("d-1", s),
        lambda s: cm.improve("d-1", s),
        lambda s: cm.retire("d-1", s),
    ):
        with pytest.raises(RetiredDraftError):
            op(seq)
        seq += 1
    cm.submit("d-2", seq)
    seq += 1
    with pytest.raises(BadReasonError):
        cm.retire("d-2", seq, reason="vibes")
    assert cm.verify("d-1", 8).posture == "approved"  # reads still work


# 12. seq discipline: rewind bare with zero rows, malformed seqs,
#     failed-mutation-consumes-seq
def test_seq_discipline():
    cm = _cm()
    cm.submit("d-1", 1)
    with pytest.raises(SeqOrderError):
        cm.submit("d-2", 1)  # rewind: bare, no new rejected row
    assert cm.stats(2)["rejected"] == 0
    for bad in (True, 0, -1, 1.5, "2", None):
        with pytest.raises(SeqOrderError):
            cm.submit("d-x", bad)
    assert cm.stats(2)["rejected"] == 0  # bare seq errors burn nothing
    with pytest.raises(BadDigestError):
        cm.submit("d-2", 3, draft_digest="raw")  # failed mutation burns seq
    assert cm.stats(4)["rejected"] == 1


# 13. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    cm = _cm()
    cm.submit("d-1", 1)
    cm.critique("d-1", 2, verdict="needs-revision")
    cm.improve("d-1", 3)
    rows = cm.audit_log(4)
    assert [r["kind"] for r in rows] == [
        "critique-model.submitted",
        "critique-model.critiqued",
        "critique-model.improved",
    ]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        for key in row["details"]:
            assert key not in (
                "draft", "critique", "text", "response", "evidence", "prompt"
            )
    with pytest.raises(AuditKindError):
        critique_model_audit_event("critiqued", 1, critique="raw text")
    with pytest.raises(AuditKindError):
        critique_model_audit_event("bogus-kind", 1)
    with pytest.raises(SeqOrderError):
        critique_model_audit_event("submitted", -1)


# 14. cross-instance digest determinism + views/stats
def test_determinism_and_views():
    def build():
        cm = _cm()
        cm.submit("d-1", 1)
        cm.critique("d-1", 2, dimension="tone", verdict="approved")
        cm.improve("d-1", 3)
        return cm

    cm1, cm2 = build(), build()
    assert cm1.draft_record("d-1", 4).digest == cm2.draft_record("d-1", 4).digest
    assert cm1.draft_ids(4) == ("d-1",)
    assert cm1.stats(4) == {
        "drafts": 1, "critiques": 1, "improvements": 1,
        "retired": 0, "rejected": 0,
    }
    with pytest.raises(UnknownCritiqueError):
        cm1.critique_record("crt-99", 4)


# 15. concurrency smoke + main() subprocess check
def test_concurrency_and_main():
    cm = _cm()
    for i in range(10):
        did = f"d{i}"
        cm.submit(did, i * 3 + 1)
        cm.critique(did, i * 3 + 2, verdict="approved")
        cm.improve(did, i * 3 + 3)
    results = []

    def worker():
        results.append(cm.draft_ids(100))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(len(r) == 10 for r in results)
    proc = subprocess.run(
        [sys.executable, "critique_model.py"],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "critique-model OK: submit, critique, improve, verify, pins, audit"
    )
