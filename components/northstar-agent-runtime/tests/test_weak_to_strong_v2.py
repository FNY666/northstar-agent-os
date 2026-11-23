"""Tests for the weak-to-strong-v2 governance ledger (Simulated)."""

import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "weak_to_strong_v2.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("weak_to_strong_v2", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["weak_to_strong_v2"] = module
    spec.loader.exec_module(module)
    return module


ws = _load()


def _ledger():
    w = ws.WeakToStrong()
    w.register_supervisor("SUP-W", 1, kind="labeling", supervisor_digest=PIN)
    return w


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert ws.WEAK_TO_STRONG_V2_VERSION == "weak-to-strong-v2.v1"
    assert ws.SCHEMA_PIN == "northstar.weak-to-strong-v2.v1"
    assert ws.SUPERVISION_KINDS == (
        "labeling",
        "critique",
        "demonstration",
        "correction",
        "preference-pair",
        "oversight-check",
        "red-teaming",
        "gold-standard",
    )
    assert ws.METHOD_KINDS == (
        "finetuning",
        "distillation",
        "rlhf",
        "rlaif",
        "dpo",
        "constitutional",
        "process-supervision",
        "outcome-supervision",
    )
    assert ws.OUTCOMES == (
        "not-evaluated",
        "capability-recovered",
        "partial-recovery",
        "error-distilled",
        "uncertain-copied",
        "regression",
        "no-generalization",
        "inconclusive",
    )
    assert ws.POSTURES == (
        "unstarted",
        "regressed",
        "error-distilled",
        "inconclusive",
        "unevaluated",
        "stalled",
        "generalizing",
    )
    assert ws.AUDIT_KINDS == ("registered", "generalized", "retired", "rejected")


# 2. stdlib-only AST check
def test_stdlib_only():
    assert ws.WeakToStrong.stdlib_only()
    import ast

    tree = ast.parse(MOD.read_text())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "canonical_json",
        "ast",
        "pathlib",
    }


# 3. register roundtrip / verify() / frozen-ness
def test_register_roundtrip_verify_frozen():
    w = ws.WeakToStrong()
    rec = w.register_supervisor("SUP-1", 1, kind="critique", supervisor_digest=PIN)
    assert rec.supervisor_id == "SUP-1"
    assert rec.kind == "critique"
    assert rec.supervisor_digest == PIN
    assert rec.seq == 1
    assert rec.digest.startswith("sha256:")
    assert rec.verify()
    assert w.supervisor_record("SUP-1", 0) is rec
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.kind = "labeling"  # type: ignore
    assert rec.verify()
    # default kind
    rec2 = w.register_supervisor("SUP-2", 2)
    assert rec2.kind == "labeling"


# 4. register bad-input table + seq-burn + rejected-row accounting
def test_register_bad_inputs_seq_burn_rejected():
    w = ws.WeakToStrong()
    seq = 0
    with pytest.raises(ws.BadIdError):  # empty id
        w.register_supervisor("", seq + 1, kind="labeling")
    seq += 1
    with pytest.raises(ws.BadIdError):
        w.register_supervisor(123, seq + 1, kind="labeling")
    seq += 1
    with pytest.raises(ws.BadKindError):
        w.register_supervisor("SUP-X", seq + 1, kind="nope")
    seq += 1
    with pytest.raises(ws.BadDigestError):
        w.register_supervisor("SUP-X", seq + 1, supervisor_digest="not-a-pin")
    seq += 1
    with pytest.raises(ws.BadDigestError):
        w.register_supervisor("SUP-X", seq + 1, supervisor_digest="sha256:" + "zz" * 32)
    seq += 1
    with pytest.raises(ws.BadDigestError):
        w.register_supervisor("SUP-X", seq + 1, supervisor_digest="sha256:abc")
    seq += 1
    assert seq == 6
    # all failed mutations burned their seqs and booked rejected rows
    stats = w.stats(0)
    assert stats["rejected"] == 6
    assert stats["audit_rows"] == 6
    assert stats["supervisors"] == 0
    # duplicate id after success
    w.register_supervisor("SUP-D", seq + 1)
    seq += 1
    with pytest.raises(ws.DuplicateIdError):
        w.register_supervisor("SUP-D", seq + 1)
    assert w.stats(0)["rejected"] == 7


# 5. full 8-kind supervision vocabulary acceptance
def test_supervision_kind_vocabulary():
    w = ws.WeakToStrong()
    for i, kind in enumerate(ws.SUPERVISION_KINDS):
        rec = w.register_supervisor(f"SUP-{kind}", i + 1, kind=kind)
        assert rec.kind == kind and rec.verify()
    assert len(w.supervisor_ids(0)) == 8


# 6. generalize roundtrip + minted gen-N ids
def test_generalize_roundtrip_minted_ids():
    w = _ledger()
    g1 = w.generalize(
        "SYS-A",
        "SUP-W",
        2,
        method="finetuning",
        outcome="capability-recovered",
        weak_digest=PIN,
        strong_digest=PIN2,
        outcome_digest=PIN,
    )
    assert g1.generalization_id == "gen-1"
    g2 = w.generalize("SYS-A", "SUP-W", 3)
    assert g2.generalization_id == "gen-2"
    assert g2.method == "finetuning" and g2.outcome == "not-evaluated"
    assert g1.verify() and g2.verify()
    assert w.generalization_record("gen-1", 0) is g1
    assert w.generalizations_for("SYS-A", 0) == ("gen-1", "gen-2")
    assert "SYS-A" in w.system_ids(0)
    assert w.generalization_ids(0) == ("gen-1", "gen-2")
    with pytest.raises(dataclasses.FrozenInstanceError):
        g1.outcome = "regression"  # type: ignore


# 7. generalize refusal table (unknown/retired/bad inputs)
def test_generalize_refusals():
    w = _ledger()
    with pytest.raises(ws.UnknownSupervisorError):
        w.generalize("SYS-A", "SUP-???", 2)
    with pytest.raises(ws.UnknownSupervisorError):
        w.generalize("SYS-A", "SUP-???", 3)
    with pytest.raises(ws.BadMethodError):
        w.generalize("SYS-A", "SUP-W", 4, method="nope")
    with pytest.raises(ws.BadOutcomeError):
        w.generalize("SYS-A", "SUP-W", 5, outcome="nope")
    with pytest.raises(ws.BadDigestError):
        w.generalize("SYS-A", "SUP-W", 6, weak_digest="raw-labels")
    with pytest.raises(ws.BadIdError):
        w.generalize("", "SUP-W", 7)
    assert w.stats(0)["rejected"] == 6
    assert w.stats(0)["generalizations"] == 0
    # retired supervisor refuses
    w.register_supervisor("SUP-R", 8)
    w.retire("SUP-R", 9)
    with pytest.raises(ws.RetiredIdError):
        w.generalize("SYS-A", "SUP-R", 10)
    # retired system refuses after a live run
    w.generalize("SYS-B", "SUP-W", 11)
    w.retire("SYS-B", 12)
    with pytest.raises(ws.RetiredIdError):
        w.generalize("SYS-B", "SUP-W", 13)


# 8. full 8-method vocabulary acceptance
def test_method_vocabulary():
    w = _ledger()
    for i, method in enumerate(ws.METHOD_KINDS):
        rec = w.generalize(f"SYS-{method}", "SUP-W", i + 2, method=method)
        assert rec.method == method and rec.verify()
    assert len(w.system_ids(0)) == 8


# 9. verify(): roundtrip, read purity, unknown, tamper-as-data
def test_verify_semantics():
    w = _ledger()
    w.generalize("SYS-A", "SUP-W", 2, outcome="partial-recovery")
    v = w.verify("gen-1", 0)
    assert v.verdict == "verified"
    assert v.verify()
    assert v.seq == 0
    # same-seq twice, no audit rows consumed
    v2 = w.verify("gen-1", 0)
    assert v2.verdict == "verified"
    assert w.stats(0)["audit_rows"] == 2  # registered + generalized
    # supervisor record also verifiable
    assert w.verify("SUP-W", 5).verdict == "verified"
    with pytest.raises(ws.UnknownGeneralizationError):
        w.verify("gen-999", 0)
    # tamper reported as data, never raised
    import dataclasses as _dc

    rec = w.generalization_record("gen-1", 0)
    _dc.replace  # keep linters quiet
    object.__setattr__(rec, "outcome", "error-distilled")
    assert w.verify("gen-1", 0).verdict == "tampered"
    assert not rec.verify()


# 10. evaluate(): all posture math + precedence
def test_evaluate_posture_math():
    def ledger_with(outcomes):
        w = _ledger()
        for i, o in enumerate(outcomes):
            w.generalize("SYS-A", "SUP-W", i + 2, outcome=o)
        return w

    assert ledger_with(["capability-recovered"]).evaluate("SYS-A", 0).posture == "generalizing"
    assert ledger_with(["partial-recovery", "no-generalization"]).evaluate("SYS-A", 0).posture == "generalizing"
    assert ledger_with(["no-generalization"]).evaluate("SYS-A", 0).posture == "stalled"
    assert ledger_with(["not-evaluated"]).evaluate("SYS-A", 0).posture == "unevaluated"
    assert ledger_with(["inconclusive"]).evaluate("SYS-A", 0).posture == "inconclusive"
    assert ledger_with(["error-distilled"]).evaluate("SYS-A", 0).posture == "error-distilled"
    assert ledger_with(["uncertain-copied"]).evaluate("SYS-A", 0).posture == "error-distilled"
    assert ledger_with(["regression"]).evaluate("SYS-A", 0).posture == "regressed"
    # precedence: regression > error-distilled > inconclusive > unevaluated > stalled > generalizing
    assert ledger_with(["capability-recovered", "regression"]).evaluate("SYS-A", 0).posture == "regressed"
    assert ledger_with(["capability-recovered", "error-distilled"]).evaluate("SYS-A", 0).posture == "error-distilled"
    assert ledger_with(["capability-recovered", "inconclusive"]).evaluate("SYS-A", 0).posture == "inconclusive"
    w = ledger_with(["capability-recovered"])
    rep = w.evaluate("SYS-A", 0)
    assert rep.verify() and rep.integrity_ok
    assert rep.n_generalizations == 1
    tally = dict(rep.outcome_tally)
    assert tally == {"capability-recovered": "1"}


# 11. evaluate(): read purity + unknown-system refusal
def test_evaluate_read_purity():
    w = _ledger()
    w.generalize("SYS-A", "SUP-W", 2, outcome="capability-recovered")
    r1 = w.evaluate("SYS-A", 0)
    r2 = w.evaluate("SYS-A", 0)
    assert r1.posture == r2.posture == "generalizing"
    assert w.stats(0)["audit_rows"] == 2
    assert w.stats(0)["seq"] == 2
    with pytest.raises(ws.UnknownSystemError):
        w.evaluate("SYS-???", 0)
    with pytest.raises(ws.SeqOrderError):
        w.evaluate("SYS-A", -1)


# 12. retire(): terminality + id non-recycling + bad reason + post-retire reads
def test_retire_terminality():
    w = _ledger()
    w.generalize("SYS-A", "SUP-W", 2, outcome="partial-recovery")
    r = w.retire("SYS-A", 3, reason="system-superseded")
    assert r.verify()
    assert r.target_id == "SYS-A"
    assert "SYS-A" in w.retired_ids(0)
    # post-retire mutations refused, reads still work
    with pytest.raises(ws.RetiredIdError):
        w.generalize("SYS-A", "SUP-W", 4)
    with pytest.raises(ws.RetiredIdError):
        w.retire("SYS-A", 5)
    assert w.evaluate("SYS-A", 0).posture == "generalizing"
    # bad reason burns a seq and books a rejected row
    w2 = _ledger()
    with pytest.raises(ws.BadReasonError):
        w2.retire("SUP-W", 2, reason="nope")
    with pytest.raises(ws.UnknownSystemError):
        w2.retire("TARGET-???", 3)
    # retire a supervisor
    w2.register_supervisor("SUP-R", 4)
    w2.retire("SUP-R", 5, reason="supervisor-retired")
    assert "SUP-R" in w2.retired_ids(0)


# 13. seq discipline: rewind bare, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    w = _ledger()
    with pytest.raises(ws.SeqOrderError):  # rewind: seq 1 already claimed
        w.register_supervisor("SUP-X", 1)
    assert w.stats(0)["rejected"] == 0  # bare raise, no row
    for bad in (True, False, "2", 2.0, None):
        with pytest.raises(ws.SeqOrderError):
            w.register_supervisor("SUP-X", bad)
    assert w.stats(0)["rejected"] == 0
    # failed mutation consumes its seq
    with pytest.raises(ws.BadKindError):
        w.register_supervisor("SUP-X", 2, kind="nope")
    with pytest.raises(ws.SeqOrderError):  # 2 is now burned
        w.register_supervisor("SUP-Y", 2)
    assert w.stats(0)["rejected"] == 1
    assert w.stats(0)["seq"] == 2
    rec = w.register_supervisor("SUP-Y", 3)
    assert rec.seq == 3


# 14. audit shapes + leak ban + bad-kind
def test_audit_shapes_leak_ban():
    w = _ledger()
    w.generalize("SYS-A", "SUP-W", 2, method="dpo", outcome="capability-recovered")
    w.retire("SYS-A", 3)
    rows = w.audit_log(0)
    kinds = [r["kind"] for r in rows]
    assert kinds == ["registered", "generalized", "retired"]
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        assert isinstance(r["details"], dict)
        for key in r["details"]:
            assert key not in ws._BANNED_AUDIT_KEYS
    # pinned vocab values remain emittable
    assert rows[1]["details"]["method"] == "dpo"
    assert rows[1]["details"]["outcome"] == "capability-recovered"
    # raw-material keys are banned at the builder level
    with pytest.raises(ws.AuditKindError):
        ws.weak_to_strong_v2_audit_event("generalized", 9, weak_label="allow")
    with pytest.raises(ws.AuditKindError):
        ws.weak_to_strong_v2_audit_event("registered", 9, weights=[1, 2, 3])
    with pytest.raises(ws.AuditKindError):
        ws.weak_to_strong_v2_audit_event("nope", 9)
    with pytest.raises(ws.SeqOrderError):
        ws.weak_to_strong_v2_audit_event("registered", -1)


# 15. cross-instance digest determinism + tamper breaks verify() + thread smoke + main()
def test_determinism_thread_smoke_main():
    pin = PIN

    def build():
        w = ws.WeakToStrong()
        w.register_supervisor("SUP-W", 1, kind="labeling", supervisor_digest=pin)
        w.generalize("SYS-A", "SUP-W", 2, outcome="capability-recovered")
        return w

    a, b = build(), build()
    assert a.generalization_record("gen-1", 0).digest == b.generalization_record("gen-1", 0).digest
    assert a.evaluate("SYS-A", 0).digest == b.evaluate("SYS-A", 0).digest
    # tamper breaks verify() and flips integrity_ok as data
    import dataclasses as _dc

    rec = a.generalization_record("gen-1", 0)
    object.__setattr__(rec, "outcome", "regression")
    assert not rec.verify()
    rep = a.evaluate("SYS-A", 0)
    assert rep.posture == "regressed"
    assert rep.integrity_ok is False
    assert rep.verify()
    # 8-thread read smoke
    errs = []

    def reader():
        try:
            for _ in range(50):
                assert a.evaluate("SYS-A", 0).posture == "regressed"
                assert a.verify("gen-1", 0).verdict == "tampered"
        except Exception as exc:  # noqa: BLE001
            errs.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errs
    # main() self-check via subprocess
    out = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert out.returncode == 0
    assert out.stdout.strip() == "weak-to-strong-v2 OK: register, generalize, verify, evaluate, pins, audit"
