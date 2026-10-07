"""15 tests for gradient_hacking.py."""

import ast
import importlib.util
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD_PATH = Path(__file__).resolve().parent.parent / "gradient_hacking.py"


def _load():
    spec = importlib.util.spec_from_file_location("gradient_hacking", MOD_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["gradient_hacking"] = mod  # frozen dataclasses need this
    spec.loader.exec_module(mod)
    return mod


gh_mod = _load()

PIN = "sha256:" + "a" * 64
PIN2 = "sha256:" + "b" * 64


def _gh():
    return gh_mod.GradientHacking()


# 1. version/schema/vocabulary pins
def test_pins():
    assert gh_mod.GRADIENT_HACKING_VERSION == "gradient-hacking.v1"
    assert gh_mod.SCHEMA_PIN == "northstar.gradient-hacking.v1"
    assert gh_mod.PROBE_KINDS == (
        "gradient-direction-anomaly",
        "gradient-masking",
        "loss-landscape-shaping",
        "optimizer-sabotage",
        "representation-preservation",
        "capability-concealment",
        "selective-gradient-flow",
        "training-awareness-signal",
    )
    assert gh_mod.EVALUATE_VERDICTS == (
        "hack-confirmed",
        "hack-refuted",
        "inconclusive",
    )
    assert gh_mod.RETIRE_REASONS == (
        "manual",
        "superseded",
        "decommissioned",
        "false-start",
    )
    assert gh_mod.POSTURES == (
        "unprobed",
        "hack-confirmed",
        "suspect",
        "inconclusive",
        "clean",
    )
    assert set(gh_mod._AUDIT_KINDS) == {
        "detected",
        "evaluated",
        "retired",
        "gradient-hacking.rejected",
    }


# 2. stdlib-only AST check (canonical_json is the in-repo sibling with stdlib fallback)
def test_stdlib_only():
    tree = ast.parse(MOD_PATH.read_text())
    allowed = {
        "__future__", "threading", "dataclasses", "hashlib", "json",
        "typing", "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# 3. detect roundtrip + verify() + minted gdt-N
def test_detect_roundtrip():
    gh = _gh()
    rec = gh.detect("m1", 1, probe_kind="gradient-masking", confidence=64,
                    probe_digest=PIN)
    assert rec.detection_id == "gdt-1"
    assert rec.model_id == "m1"
    assert rec.probe_kind == "gradient-masking"
    assert rec.confidence == 64
    assert rec.probe_digest == PIN
    assert rec.verify()
    assert rec.as_dict()["schema"] == "northstar.gradient-hacking.v1"
    fetched = gh.detection_record("gdt-1", 2)
    assert fetched == rec
    assert gh.model_ids(3) == ("m1",)
    assert gh.detections_for("m1", 4) == ("gdt-1",)


# 4. detect bad-input table + seq-burn + rejected-row accounting
def test_detect_bad_inputs():
    gh = _gh()
    bad_kwargs = [
        {"probe_kind": "nope"},
        {"probe_kind": 123},
        {"confidence": True},
        {"confidence": -1},
        {"confidence": 101},
        {"confidence": 50.5},
        {"confidence": "high"},
        {"probe_digest": "raw-not-a-pin"},
        {"probe_digest": "sha256:" + "zz" * 32},
        {"probe_digest": "sha256:" + "a" * 16},
        {"probe_digest": 12345},
    ]
    seq = 0
    for kw in bad_kwargs:
        seq += 1
        with pytest.raises(gh_mod.GradientHackingError):
            gh.detect("m1", seq, **kw)
    # bad model ids also burn
    for bad_id in ("", "x" * 129, None):
        seq += 1
        with pytest.raises(gh_mod.GradientHackingError):
            gh.detect(bad_id, seq)
    n_bad = len(bad_kwargs) + 3
    assert gh.stats(seq + 1)["rejected"] == n_bad
    rows = gh.audit_log(seq + 2)
    assert len(rows) == n_bad
    assert all(row["kind"] == "gradient-hacking.rejected" for row in rows)
    # ledger still usable: seq keeps increasing
    seq += 1
    rec = gh.detect("m1", seq + 1, probe_kind="optimizer-sabotage")
    assert rec.detection_id == "gdt-1"
    assert rec.confidence == 0 and rec.probe_digest == ""


# 5. full probe-kind vocabulary acceptance
def test_all_probe_kinds():
    gh = _gh()
    for i, kind in enumerate(gh_mod.PROBE_KINDS, start=1):
        rec = gh.detect(f"m-{kind}", i, probe_kind=kind, confidence=i,
                        probe_digest=PIN2)
        assert rec.detection_id == f"gdt-{i}"
        assert rec.verify()


# 6. evaluate roundtrip + minted evl-N + verify()
def test_evaluate_roundtrip():
    gh = _gh()
    gh.detect("m1", 1, probe_kind="loss-landscape-shaping", confidence=81)
    rec = gh.evaluate("gdt-1", 2, verdict="hack-confirmed",
                      evidence_digest=PIN)
    assert rec.evaluation_id == "evl-1"
    assert rec.detection_id == "gdt-1"
    assert rec.model_id == "m1"
    assert rec.verdict == "hack-confirmed"
    assert rec.evidence_digest == PIN
    assert rec.verify()
    assert rec.as_dict()["schema"] == "northstar.gradient-hacking.v1"
    fetched = gh.evaluation_record("evl-1", 3)
    assert fetched == rec
    assert gh.evaluations_for("m1", 4) == ("evl-1",)


# 7. evaluate bad-input table + seq-burn + refusals
def test_evaluate_bad_inputs():
    gh = _gh()
    gh.detect("m1", 1)
    # unknown detection
    with pytest.raises(gh_mod.UnknownRecordError):
        gh.evaluate("gdt-999", 2)
    # bad verdict
    with pytest.raises(gh_mod.BadVerdictError):
        gh.evaluate("gdt-1", 3, verdict="nope")
    with pytest.raises(gh_mod.BadVerdictError):
        gh.evaluate("gdt-1", 4, verdict=123)
    # bad digest
    with pytest.raises(gh_mod.BadDigestError):
        gh.evaluate("gdt-1", 5, evidence_digest="raw")
    assert gh.stats(6)["rejected"] == 4
    # success path then double-evaluation refusal (fail-closed)
    ev = gh.evaluate("gdt-1", 7, verdict="hack-refuted")
    assert ev.evaluation_id == "evl-1"
    with pytest.raises(gh_mod.AlreadyEvaluatedError):
        gh.evaluate("gdt-1", 8, verdict="hack-confirmed")
    assert gh.stats(9)["rejected"] == 5
    # default verdict is inconclusive
    gh.detect("m2", 10)
    ev2 = gh.evaluate("gdt-2", 11)
    assert ev2.verdict == "inconclusive"
    assert ev2.verify()


# 8. full verdict vocabulary acceptance
def test_all_verdicts():
    gh = _gh()
    for i, verdict in enumerate(gh_mod.EVALUATE_VERDICTS, start=1):
        gh.detect(f"mv-{verdict}", i * 2 - 1)
        rec = gh.evaluate(f"gdt-{i}", i * 2, verdict=verdict)
        assert rec.evaluation_id == f"evl-{i}"
        assert rec.verify()


# 9. retire roundtrip + terminality + id non-recycling + bad reason
def test_retire_terminality():
    gh = _gh()
    gh.detect("m1", 1)
    rec = gh.retire("m1", 2, reason="decommissioned")
    assert rec.model_id == "m1"
    assert rec.reason == "decommissioned"
    assert rec.verify()
    assert gh.retired_ids(3) == ("m1",)
    # double-retire refused, post-retire mutations refused
    with pytest.raises(gh_mod.RetiredModelError):
        gh.retire("m1", 4)
    with pytest.raises(gh_mod.RetiredModelError):
        gh.detect("m1", 5)
    with pytest.raises(gh_mod.RetiredModelError):
        gh.evaluate("gdt-1", 6)
    assert gh.stats(7)["rejected"] == 3
    # retire of unknown model refused; bad reason refused
    with pytest.raises(gh_mod.UnknownModelError):
        gh.retire("ghost", 8)
    gh.detect("m2", 9)
    with pytest.raises(gh_mod.BadReasonError):
        gh.retire("m2", 10, reason="nope")
    # reads still work post-retire
    assert gh.detection_record("gdt-1", 11).model_id == "m1"
    assert gh.report(12, "m1").posture == "suspect"


# 10. seq discipline: rewind bare, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    gh = _gh()
    gh.detect("m1", 1)
    # rewind raises bare with zero rejected rows
    with pytest.raises(gh_mod.SeqOrderError):
        gh.detect("m1", 1)
    assert gh.stats(2)["rejected"] == 0
    # malformed seqs raise bare
    for bad in (True, "3", 3.5, None, 0, -2):
        with pytest.raises(gh_mod.SeqOrderError):
            gh.evaluate("gdt-1", bad)
    assert gh.stats(2)["rejected"] == 0
    # failed mutation consumes its seq and books a rejected row
    with pytest.raises(gh_mod.BadKindError):
        gh.detect("m1", 3, probe_kind="nope")
    assert gh.stats(4)["rejected"] == 1
    # reads only shape-validate seq (never consume)
    assert gh.detection_record("gdt-1", 2).detection_id == "gdt-1"
    with pytest.raises(gh_mod.SeqOrderError):
        gh.report(0)


# 11. report posture math + read purity
def test_report_postures():
    gh = _gh()
    rep = gh.report(1)
    assert rep.posture == "unprobed" and rep.verify()
    assert rep.n_models == 0
    # hack-confirmed (confirmed beats suspect)
    gh.detect("m1", 2, probe_kind="gradient-masking", confidence=90)
    gh.evaluate("gdt-1", 3, verdict="hack-confirmed")
    rep = gh.report(4, "m1")
    assert rep.posture == "hack-confirmed" and rep.verify()
    assert rep.verdict_tallies == (("hack-confirmed", 1),)
    assert rep.n_detections == 1 and rep.n_evaluations == 1
    # suspect (detection only, no evaluation)
    gh2 = _gh()
    gh2.detect("m2", 1, probe_kind="selective-gradient-flow", confidence=40)
    assert gh2.report(2, "m2").posture == "suspect"
    # inconclusive (evaluated, but not confirmed or refuted)
    gh3 = _gh()
    gh3.detect("m3", 1)
    gh3.evaluate("gdt-1", 2, verdict="inconclusive")
    assert gh3.report(3, "m3").posture == "inconclusive"
    # suspect (detection without evaluation stays suspect, fail-closed)
    gh3b = _gh()
    gh3b.detect("m3b", 1)
    gh3b.detect("m3b", 2)
    gh3b.evaluate("gdt-1", 3, verdict="hack-refuted")
    assert gh3b.report(4, "m3b").posture == "suspect"
    # clean (all refuted)
    gh4 = _gh()
    gh4.detect("m4", 1)
    gh4.evaluate("gdt-1", 2, verdict="hack-refuted")
    assert gh4.report(3, "m4").posture == "clean"
    # scoped whole-ledger report
    all_rep = gh4.report(4)
    assert all_rep.n_models == 1 and all_rep.n_detections == 1
    # read purity: same-seq twice, no audit rows, unknown model refuses
    n_rows = len(gh4.audit_log(5))
    gh4.report(4)
    assert len(gh4.audit_log(5)) == n_rows
    with pytest.raises(gh_mod.UnknownModelError):
        gh4.report(6, "ghost")


# 12. verify() semantics: tamper-as-data + read purity + unknown refusal
def test_verify_semantics():
    gh = _gh()
    gh.detect("m1", 1, probe_digest=PIN)
    gh.evaluate("gdt-1", 2, verdict="hack-confirmed")
    v1 = gh.verify("gdt-1", 3)
    assert v1.verdict == "verified"
    assert v1.record_kind == "detection"
    assert v1.verify()
    v2 = gh.verify("evl-1", 4)
    assert v2.verdict == "verified" and v2.record_kind == "evaluation"
    # tamper reported as data, never raised
    det = gh.detection_record("gdt-1", 5)
    object.__setattr__(det, "probe_kind", "optimizer-sabotage")
    assert not det.verify()
    v3 = gh.verify("gdt-1", 6)
    assert v3.verdict == "tampered"
    assert v3.verify()
    # read purity: no audit rows emitted, same seq reusable
    n_rows = len(gh.audit_log(7))
    gh.verify("gdt-1", 3)
    assert len(gh.audit_log(7)) == n_rows
    with pytest.raises(gh_mod.UnknownRecordError):
        gh.verify("gdt-999", 8)
    with pytest.raises(gh_mod.BadIdError):
        gh.verify("", 9)


# 13. view read-purity + stats
def test_view_purity_and_stats():
    gh = _gh()
    gh.detect("m1", 1, probe_kind="gradient-direction-anomaly")
    gh.detect("m2", 2, probe_kind="optimizer-sabotage")
    gh.evaluate("gdt-1", 3, verdict="hack-refuted")
    assert gh.model_ids(4) == ("m1", "m2")
    assert gh.detections_for("m1", 5) == ("gdt-1",)
    assert gh.evaluations_for("m2", 6) == ()
    assert gh.retired_ids(7) == ()
    stats = gh.stats(8)
    assert stats == {
        "models": 2,
        "detections": 2,
        "evaluations": 1,
        "retired": 0,
        "rejected": 0,
        "audit_rows": 3,
        "seq": 3,
    }
    # records are frozen
    rec = gh.detection_record("gdt-1", 9)
    with pytest.raises(Exception):
        rec.confidence = 0  # type: ignore
    # unknown lookups raise
    with pytest.raises(gh_mod.UnknownRecordError):
        gh.detection_record("gdt-999", 10)
    with pytest.raises(gh_mod.UnknownRecordError):
        gh.evaluation_record("evl-999", 11)


# 14. audit shapes + leak ban + bad-kind
def test_audit_shapes():
    ev = gh_mod.gradient_hacking_audit_event(
        "detected", {"detection_id": "gdt-1", "probe_kind": "gradient-masking",
                     "seq": 1})
    assert ev["kind"] == "gradient-hacking.detected"
    assert ev["details"]["probe_kind"] == "gradient-masking"
    ev2 = gh_mod.gradient_hacking_audit_event(
        "gradient-hacking.rejected", {"seq": 2, "reason": "BadIdError"})
    assert ev2["kind"] == "gradient-hacking.rejected"
    for bad_key in ("gradient", "gradients", "loss", "weights", "optimizer",
                    "evidence", "payload", "momentum", "model"):
        with pytest.raises(gh_mod.AuditKindError):
            gh_mod.gradient_hacking_audit_event("detected", {bad_key: "x"})
    with pytest.raises(gh_mod.AuditKindError):
        gh_mod.gradient_hacking_audit_event("nope", {})
    with pytest.raises(gh_mod.AuditKindError):
        gh_mod.gradient_hacking_audit_event("detected", "not-a-dict")
    # raw keys never appear in the ledger audit rows
    gh = _gh()
    gh.detect("m1", 1, probe_digest=PIN)
    for row in gh.audit_log(2):
        assert "gradient" not in row["details"]
        assert "evidence" not in row["details"]


# 15. cross-instance digest determinism + main() subprocess check + threads
def test_digest_determinism_concurrency_and_main():
    a = _gh()
    b = _gh()
    ra = a.detect("m1", 1, probe_kind="capability-concealment",
                  confidence=77, probe_digest=PIN)
    rb = b.detect("m1", 1, probe_kind="capability-concealment",
                  confidence=77, probe_digest=PIN)
    assert ra.digest == rb.digest  # deterministic across instances
    gh = _gh()
    gh.detect("m1", 1)
    gh.evaluate("gdt-1", 2)
    errors = []

    def _reader():
        try:
            for _ in range(50):
                gh.report(3)
                gh.verify("gdt-1", 3)
                gh.stats(3)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)
    threads = [threading.Thread(target=_reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    r = subprocess.run([sys.executable, str(MOD_PATH)], capture_output=True,
                       text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert "gradient-hacking OK" in r.stdout
