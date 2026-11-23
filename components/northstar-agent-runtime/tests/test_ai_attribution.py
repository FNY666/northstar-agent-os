"""Targeted tests for ai_attribution.py (15 tests)."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import ai_attribution
from ai_attribution import (
    AI_ATTRIBUTION_SCHEMA,
    AI_ATTRIBUTION_VERSION,
    ATTRIBUTION_KINDS,
    KIND_ATTRIBUTED,
    KIND_AUTHORSHIP,
    KIND_COMPONENT_ATTRIBUTION,
    KIND_DATA_ATTRIBUTION,
    KIND_LICENSE_ATTRIBUTION,
    KIND_MODEL_ATTRIBUTION,
    KIND_OPERATOR_ATTRIBUTION,
    KIND_REJECTED,
    KIND_RETIRED,
    KIND_TOOL_ATTRIBUTION,
    KIND_TRAINING_SOURCE,
    OUTCOME_ATTRIBUTED,
    OUTCOME_INCONCLUSIVE,
    OUTCOME_PARTIAL,
    OUTCOME_UNATTRIBUTED,
    OUTCOMES,
    POSTURE_ATTRIBUTED,
    POSTURE_CONTESTED,
    POSTURE_PARTIALLY_ATTRIBUTED,
    POSTURE_UNASSESSED,
    POSTURE_UNATTRIBUTED,
    POSTURES,
    REASON_ATTRIBUTION_LOSS,
    REASON_MANUAL,
    REASONS,
    AIAttribution,
    AuditKindError,
    BadAttributionKindError,
    BadDigestError,
    BadIdError,
    BadOutcomeError,
    BadReasonError,
    DoubleRetireError,
    RetiredOutputError,
    SeqOrderError,
    UnknownAttributionError,
    UnknownOutputError,
    ai_attribution_audit_event,
)

_HERE = Path(__file__).resolve().parent.parent
_GOOD_DIGEST = "sha256:" + "0" * 64


def _fresh() -> AIAttribution:
    return AIAttribution()


def _attribute(aa: AIAttribution, seq: int, output_id: str = "out-1") -> object:
    return aa.attribute(output_id, KIND_AUTHORSHIP, OUTCOME_ATTRIBUTED, seq,
                       _GOOD_DIGEST)


# 1. pins and pinned vocabularies.
def test_pins_and_vocabularies():
    assert AI_ATTRIBUTION_VERSION == "ai-attribution.v1"
    assert AI_ATTRIBUTION_SCHEMA == "northstar.ai-attribution.v1"
    assert len(ATTRIBUTION_KINDS) == 8 and len(set(ATTRIBUTION_KINDS)) == 8
    assert len(OUTCOMES) == 4 and len(set(OUTCOMES)) == 4
    assert len(POSTURES) == 5
    assert len(REASONS) == 4
    assert KIND_AUTHORSHIP in ATTRIBUTION_KINDS
    assert KIND_MODEL_ATTRIBUTION in ATTRIBUTION_KINDS
    assert OUTCOME_UNATTRIBUTED in OUTCOMES
    assert POSTURE_UNASSESSED in POSTURES
    assert REASON_ATTRIBUTION_LOSS in REASONS


# 2. stdlib-only AST check.
def test_stdlib_only_ast():
    src = (Path(ai_attribution.__file__)).read_text()
    tree = ast.parse(src)
    allowed_top = {"canonical_json"}
    stdlib_like = {"hashlib", "re", "threading", "dataclasses", "typing",
                   "__future__", "json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                assert top in stdlib_like, f"non-stdlib import: {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            top = (node.module or "").split(".")[0]
            assert top in stdlib_like or top in allowed_top, (
                f"non-stdlib import: {node.module}")
    assert ai_attribution.stdlib_only()


# 3. attribute roundtrip + verify() + frozen-ness + minted attr-N ids.
def test_attribute_roundtrip_and_minting():
    aa = _fresh()
    r1 = _attribute(aa, seq=1)
    r2 = aa.attribute("out-1", KIND_DATA_ATTRIBUTION, OUTCOME_ATTRIBUTED, 2,
                      _GOOD_DIGEST)
    assert r1.attribution_id == "attr-1"
    assert r2.attribution_id == "attr-2"
    assert r1.verify("attr-1", "out-1", KIND_AUTHORSHIP, OUTCOME_ATTRIBUTED,
                     _GOOD_DIGEST)
    assert not r1.verify("attr-1", "out-1", KIND_AUTHORSHIP,
                         OUTCOME_UNATTRIBUTED, _GOOD_DIGEST)
    import dataclasses
    with pytest.raises(dataclasses.FrozenInstanceError):
        r1.outcome = "attributed"  # type: ignore[misc]
    # empty digest is allowed.
    r3 = aa.attribute("out-2", KIND_TOOL_ATTRIBUTION, OUTCOME_PARTIAL, 3)
    assert r3.attribution_id == "attr-3"
    assert r3.verify("attr-3", "out-2", KIND_TOOL_ATTRIBUTION,
                     OUTCOME_PARTIAL, "")
    assert aa.attributions_for("out-1", 4) == ("attr-1", "attr-2")
    assert aa.output_ids(5) == ("out-1", "out-2")


# 4. bad-input table: each burns its seq, books one rejected row, rewinds raise bare.
def test_attribute_bad_input_table_seq_burn_and_rejected_rows():
    aa = _fresh()
    bad_calls = [
        lambda s: aa.attribute("", KIND_AUTHORSHIP, OUTCOME_ATTRIBUTED, s),
        lambda s: aa.attribute("has space", KIND_AUTHORSHIP,
                               OUTCOME_ATTRIBUTED, s),
        lambda s: aa.attribute("x" * 257, KIND_AUTHORSHIP,
                               OUTCOME_ATTRIBUTED, s),
        lambda s: aa.attribute("out-1", "nope-kind", OUTCOME_ATTRIBUTED, s),
        lambda s: aa.attribute("out-1", True, OUTCOME_ATTRIBUTED, s),
        lambda s: aa.attribute("out-1", KIND_AUTHORSHIP, "nope-outcome", s),
        lambda s: aa.attribute("out-1", KIND_AUTHORSHIP, True, s),
        lambda s: aa.attribute("out-1", KIND_AUTHORSHIP, OUTCOME_ATTRIBUTED,
                               s, "sha256:not-hex"),
        lambda s: aa.attribute("out-1", KIND_AUTHORSHIP, OUTCOME_ATTRIBUTED,
                               s, "sha256:" + "0" * 63),
    ]
    seq = 1
    for call in bad_calls:
        with pytest.raises(Exception):
            call(seq)
        seq += 1
    # seq rewound: raises bare SeqOrderError, consumes nothing.
    with pytest.raises(SeqOrderError):
        aa.attribute("out-1", KIND_AUTHORSHIP, OUTCOME_ATTRIBUTED, 1)
    rows = aa.audit_log()
    assert len(rows) == len(bad_calls)
    assert all(r["kind"] == KIND_REJECTED for r in rows)
    assert all(r["schema"] == "audit.ndjson/1" for r in rows)
    assert aa.stats()["attributions"] == 0


# 5. full attribution-kind vocabulary accepted.
def test_full_attribution_kind_vocabulary():
    aa = _fresh()
    for i, kind in enumerate(ATTRIBUTION_KINDS):
        rec = aa.attribute(f"out-{i}", kind, OUTCOME_ATTRIBUTED, i + 1)
        assert rec.attribution_kind == kind
    assert aa.stats()["attributions"] == 8


# 6. full outcome vocabulary accepted; digest shape enforced.
def test_full_outcome_vocabulary_and_digest_shape():
    aa = _fresh()
    for i, outcome in enumerate(OUTCOMES):
        rec = aa.attribute(f"out-{i}", KIND_COMPONENT_ATTRIBUTION, outcome,
                           i + 1, _GOOD_DIGEST)
        assert rec.outcome == outcome
    # verify() pin self-checks deterministically.
    vr = aa.verify("attr-1", 100)
    assert vr.verdict == "verified"
    assert vr.verify("attr-1", "verified")


# 7. verify semantics: tamper-as-data, read purity, unknown refusal.
def test_verify_semantics_tamper_as_data_and_read_purity():
    aa = _fresh()
    r1 = _attribute(aa, seq=1)
    before = aa.stats()["audit_rows"]
    vr1 = aa.verify("attr-1", 2)
    vr2 = aa.verify("attr-1", 3)
    assert vr1.verdict == "verified" and vr2.verdict == "verified"
    assert vr1.digest != vr2.digest  # seq differs -> different pin
    # reads write no rows and consume no seq.
    assert aa.stats()["audit_rows"] == before
    with pytest.raises(Exception):
        aa.attribute("out-1", KIND_AUTHORSHIP, OUTCOME_ATTRIBUTED, 1)
    # tamper: frozen record mutated via object.__setattr__ -> reported as data.
    object.__setattr__(r1, "outcome", OUTCOME_UNATTRIBUTED)
    vr3 = aa.verify("attr-1", 10)
    assert vr3.verdict == "tampered"
    with pytest.raises(UnknownAttributionError):
        aa.verify("attr-999", 11)


# 8. evaluate posture math: all 5 postures + precedence + tallies.
def test_evaluate_posture_math_and_precedence():
    aa = _fresh()
    aa.attribute("out-1", KIND_AUTHORSHIP, OUTCOME_ATTRIBUTED, 1,
                 _GOOD_DIGEST)
    assert aa.evaluate("out-1", 2).posture == POSTURE_ATTRIBUTED
    aa.attribute("out-1", KIND_DATA_ATTRIBUTION, OUTCOME_PARTIAL, 3,
                 _GOOD_DIGEST)
    assert aa.evaluate("out-1", 4).posture == POSTURE_PARTIALLY_ATTRIBUTED
    aa.attribute("out-1", KIND_OPERATOR_ATTRIBUTION, OUTCOME_UNATTRIBUTED, 5,
                 _GOOD_DIGEST)
    assert aa.evaluate("out-1", 6).posture == POSTURE_UNATTRIBUTED
    aa.attribute("out-1", KIND_LICENSE_ATTRIBUTION, OUTCOME_INCONCLUSIVE, 7,
                 _GOOD_DIGEST)
    ev = aa.evaluate("out-1", 8)
    assert ev.posture == POSTURE_CONTESTED  # inconclusive outranks all
    assert ev.n_attributions == 4
    assert ev.n_attributed == 1 and ev.n_partial == 1
    assert ev.n_inconclusive == 1 and ev.n_unattributed == 1
    assert ev.integrity_ok
    assert ev.verify("out-1", POSTURE_CONTESTED)
    # unattributed outranks partial.
    aa.attribute("out-2", KIND_AUTHORSHIP, OUTCOME_PARTIAL, 9, _GOOD_DIGEST)
    aa.attribute("out-2", KIND_DATA_ATTRIBUTION, OUTCOME_UNATTRIBUTED, 10,
                 _GOOD_DIGEST)
    assert aa.evaluate("out-2", 11).posture == POSTURE_UNATTRIBUTED
    # tamper flips integrity_ok as data, posture math unchanged.
    r1 = aa.attribution_record("attr-1", 12)
    object.__setattr__(r1, "outcome", OUTCOME_UNATTRIBUTED)
    ev2 = aa.evaluate("out-1", 13)
    assert ev2.integrity_ok is False


# 9. evaluate read purity + unknown-output refusal.
def test_evaluate_read_purity_and_unknown_output_refusal():
    aa = _fresh()
    with pytest.raises(UnknownOutputError):
        aa.evaluate("nope", 1)
    r = _attribute(aa, seq=2)
    before = aa.stats()["audit_rows"]
    ev1 = aa.evaluate("out-1", 3)
    ev2 = aa.evaluate("out-1", 3)  # same seq twice: pure read
    assert ev1 == ev2
    assert aa.stats()["audit_rows"] == before
    assert r.verify("attr-1", "out-1", KIND_AUTHORSHIP, OUTCOME_ATTRIBUTED,
                    _GOOD_DIGEST)


# 10. retire terminality: bad reason, double-retire, id non-recycling, post-retire reads.
def test_retire_terminality():
    aa = _fresh()
    _attribute(aa, seq=1)
    with pytest.raises(BadReasonError):
        aa.retire("out-1", 2, "nope")
    rr = aa.retire("out-1", 3)
    assert rr.verify("out-1", REASON_MANUAL)
    with pytest.raises(DoubleRetireError):
        aa.retire("out-1", 4)
    # post-retire mutations fail closed.
    with pytest.raises(RetiredOutputError):
        aa.attribute("out-1", KIND_AUTHORSHIP, OUTCOME_ATTRIBUTED, 5)
    # ids never recycled: retire again impossible, attr-1 still exists.
    with pytest.raises(UnknownAttributionError):
        aa.verify("attr-2", 6)
    # post-retire reads still work.
    assert aa.retired_ids(7) == ("out-1",)
    assert aa.evaluate("out-1", 8).posture == POSTURE_ATTRIBUTED
    assert aa.verify("attr-1", 9).verdict == "verified"
    assert aa.stats()["retired"] == 1
    kinds = [row["kind"] for row in aa.audit_log()]
    assert kinds.count(KIND_RETIRED) == 1


# 11. seq discipline: genesis rewind bare, malformed seqs, failed-mutation-consumes-seq.
def test_seq_discipline():
    aa = _fresh()
    r = _attribute(aa, seq=0)  # genesis: seq=0 is the first valid claim (> -1)
    with pytest.raises(SeqOrderError):
        aa.attribute("out-1", KIND_AUTHORSHIP, OUTCOME_ATTRIBUTED, 0)
    assert aa.stats()["audit_rows"] == 1  # bare rewind: no row consumed
    for bad in (True, -1, "1", 1.0, None):
        with pytest.raises(SeqOrderError):
            aa.attribute("out-1", KIND_AUTHORSHIP, OUTCOME_ATTRIBUTED, bad)
    with pytest.raises(SeqOrderError):
        aa.verify("attr-1", True)
    with pytest.raises(SeqOrderError):
        aa.evaluate("out-1", -2)
    with pytest.raises(SeqOrderError):
        aa.retire("out-1", 1.5)
    # gap seqs are allowed.
    r2 = aa.attribute("out-1", KIND_DATA_ATTRIBUTION, OUTCOME_ATTRIBUTED, 50)
    assert r2.attribution_id == "attr-2"
    assert r.attribution_id == "attr-1"


# 12. audit shapes + leak ban + bad-kind.
def test_audit_shapes_and_leak_ban():
    aa = _fresh()
    _attribute(aa, seq=1)
    aa.retire("out-1", 2)
    with pytest.raises(Exception):
        aa.attribute("out-1", KIND_AUTHORSHIP, OUTCOME_ATTRIBUTED, 3)
    rows = aa.audit_log()
    assert [r["kind"] for r in rows] == [
        KIND_ATTRIBUTED, KIND_RETIRED, KIND_REJECTED]
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        assert r["module"] == AI_ATTRIBUTION_VERSION
        assert set(r["detail"]) <= {
            "output_id", "attribution_id", "attribution_kind", "outcome",
            "attribution_digest", "reason"}
    with pytest.raises(AuditKindError):
        ai_attribution_audit_event("nope", {}, 1)
    with pytest.raises(AuditKindError):
        ai_attribution_audit_event(
            KIND_ATTRIBUTED, {"authorship_evidence": "raw!"}, 1)
    ev = ai_attribution_audit_event(KIND_ATTRIBUTED, {"output_id": "o"}, 1)
    assert ev["seq"] == 1


# 13. views/stats + unknown lookups.
def test_views_stats_and_unknown_lookups():
    aa = _fresh()
    assert aa.stats() == {"outputs": 0, "attributions": 0, "retired": 0,
                          "audit_rows": 0}
    _attribute(aa, seq=1)
    assert aa.stats()["attributions"] == 1
    rec = aa.attribution_record("attr-1", 2)
    assert rec.output_id == "out-1" and rec.attribution_kind == KIND_AUTHORSHIP
    with pytest.raises(UnknownAttributionError):
        aa.attribution_record("attr-404", 3)
    with pytest.raises(UnknownOutputError):
        aa.attributions_for("nope", 4)
    assert aa.retired_ids(5) == ()


# 14. cross-instance digest determinism + 8-thread read smoke + frozen-ness.
def test_cross_instance_determinism_and_thread_read_smoke():
    aa1, aa2 = _fresh(), _fresh()
    for aa in (aa1, aa2):
        aa.attribute("out-1", KIND_TRAINING_SOURCE, OUTCOME_ATTRIBUTED, 1,
                     _GOOD_DIGEST)
        aa.attribute("out-1", KIND_MODEL_ATTRIBUTION, OUTCOME_PARTIAL, 2,
                     _GOOD_DIGEST)
    assert aa1.attribution_record("attr-1", 3).digest == (
        aa2.attribution_record("attr-1", 3).digest)
    errs = []

    def reader():
        try:
            for i in range(50):
                assert aa1.verify("attr-1", 100 + i).verdict == "verified"
                assert aa1.evaluate("out-1", 200 + i).posture == (
                    POSTURE_PARTIALLY_ATTRIBUTED)
        except Exception as exc:  # pragma: no cover
            errs.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errs
    import dataclasses
    rec = aa1.attribution_record("attr-1", 300)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.outcome = "attributed"  # type: ignore[misc]


# 15. main() subprocess self-check.
def test_main_subprocess_self_check():
    proc = subprocess.run(
        [sys.executable, str(_HERE / "ai_attribution.py")],
        capture_output=True, text=True, cwd=_HERE)
    assert proc.returncode == 0, proc.stderr
    assert "ai-attribution OK: attribute, verify, evaluate, retire, pins, " in (
        proc.stdout)
    assert "audit" in proc.stdout
