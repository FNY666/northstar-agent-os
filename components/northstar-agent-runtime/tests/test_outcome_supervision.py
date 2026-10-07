"""Tests for the outcome-supervision governance ledger (Simulated)."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "outcome_supervision.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("outcome_supervision", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["outcome_supervision"] = module
    spec.loader.exec_module(module)
    return module


os = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert os.OUTCOME_SUPERVISION_VERSION == "outcome-supervision.v1"
    assert os.SCHEMA_PIN == "northstar.outcome-supervision.v1"
    assert os.SUPERVISION_KINDS == (
        "human-review",
        "model-judge",
        "programmatic-check",
        "spot-check",
        "sampling-audit",
        "consensus-vote",
    )
    assert os.OUTCOME_VERDICTS == ("accepted", "rejected", "flagged", "escalated")
    assert os.RETIRE_REASONS == (
        "manual",
        "task-superseded",
        "protocol-complete",
        "invalidated",
    )
    assert os.POSTURES == (
        "unsupervised",
        "rejected-open",
        "escalated",
        "flagged",
        "accepted",
    )
    assert os.AUDIT_KINDS == ("supervised", "retired", "rejected")


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(MOD.read_text())
    allowed = {
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
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= allowed, imports - allowed
    assert os.OutcomeSupervision.stdlib_only()


# 3. supervise() roundtrip + minted ids + record verify + frozen-ness
def test_supervise_roundtrip():
    o = os.OutcomeSupervision()
    rec = o.supervise(
        "TASK-1",
        1,
        supervision_kind="human-review",
        outcome_verdict="accepted",
        task_digest=PIN,
        outcome_digest=PIN2,
    )
    assert rec.supervision_id == "sup-1"
    assert rec.task_id == "TASK-1"
    assert rec.supervision_kind == "human-review"
    assert rec.outcome_verdict == "accepted"
    assert rec.task_digest == PIN
    assert rec.outcome_digest == PIN2
    assert rec.verify()
    assert rec.as_dict()["schema"] == os.SCHEMA_PIN
    with pytest.raises(Exception):
        rec.outcome_verdict = "rejected"  # frozen
    rec2 = o.supervise("TASK-1", 2)
    assert rec2.supervision_id == "sup-2"
    assert o.supervisions_for("TASK-1", 0) == ("sup-1", "sup-2")
    assert o.supervision_record("sup-1", 0).verify()
    rows = o.audit_log(0)
    assert rows[-1]["kind"] == "supervised"
    assert rows[-1]["details"]["supervision_id"] == "sup-2"
    assert rows[-1]["details"]["outcome_verdict"] == "accepted"


# 4. supervise bad-input table + seq-burn + rejected-row accounting
def test_supervise_bad_inputs_and_seq_burn():
    o = os.OutcomeSupervision()
    seq = 0
    seq += 1
    o.supervise("TASK-1", seq)
    bad = [
        (lambda s: o.supervise("", s), os.BadIdError),
        (lambda s: o.supervise(123, s), os.BadIdError),
        (lambda s: o.supervise("TASK-2", s, supervision_kind="tea-leaves"), os.BadKindError),
        (lambda s: o.supervise("TASK-2", s, outcome_verdict="shrugged"), os.BadVerdictError),
        (lambda s: o.supervise("TASK-2", s, task_digest="raw-bytes"), os.BadDigestError),
        (lambda s: o.supervise("TASK-2", s, task_digest="md5:abc"), os.BadDigestError),
        (lambda s: o.supervise("TASK-2", s, outcome_digest="raw-bytes"), os.BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    rows = o.audit_log(0)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == len(bad)
    assert all(r["schema"] == "audit.ndjson/1" for r in rejected)
    # retired-task refusal books a rejected row too
    seq += 1
    o.retire("TASK-1", seq)
    seq += 1
    with pytest.raises(os.RetiredTaskError):
        o.supervise("TASK-1", seq)
    rejected = [r for r in o.audit_log(0) if r["kind"] == "rejected"]
    assert len(rejected) == len(bad) + 1


# 5. full supervision-kind x outcome-verdict vocabulary acceptance
def test_full_vocabulary():
    o = os.OutcomeSupervision()
    seq = 0
    n = 0
    for i, kind in enumerate(os.SUPERVISION_KINDS):
        for j, verdict in enumerate(os.OUTCOME_VERDICTS):
            seq += 1
            rec = o.supervise(f"VOC-{i}-{j}", seq, supervision_kind=kind, outcome_verdict=verdict)
            assert rec.verify()
            n += 1
    assert n == len(os.SUPERVISION_KINDS) * len(os.OUTCOME_VERDICTS) == 24
    assert o.task_ids(0)[0] == "VOC-0-0"
    assert len(o.supervision_ids(0)) == 24


# 6. evaluate() posture math + verdict tally + unknown-task refusal
def test_evaluate_posture_math():
    o = os.OutcomeSupervision()
    o.supervise("T-ACC", 1, outcome_verdict="accepted")
    o.supervise("T-ACC", 2, outcome_verdict="accepted")
    o.supervise("T-REJ", 3, outcome_verdict="accepted")
    o.supervise("T-REJ", 4, outcome_verdict="rejected")
    o.supervise("T-ESC", 5, outcome_verdict="escalated")
    o.supervise("T-FLG", 6, outcome_verdict="flagged")
    e_acc = o.evaluate("T-ACC", 0)
    e_rej = o.evaluate("T-REJ", 0)
    e_esc = o.evaluate("T-ESC", 0)
    e_flg = o.evaluate("T-FLG", 0)
    assert e_acc.posture == "accepted" and e_acc.verify() and e_acc.integrity_ok
    assert e_rej.posture == "rejected-open"
    assert e_esc.posture == "escalated"
    assert e_flg.posture == "flagged"
    assert e_acc.n_supervisions == 2
    tally = dict(e_rej.verdict_tally)
    assert tally["accepted"] == 1 and tally["rejected"] == 1
    assert tally["flagged"] == 0 and tally["escalated"] == 0
    with pytest.raises(os.UnknownTaskError):
        o.evaluate("T-GHOST", 0)


# 7. verify() read semantics + tamper reported as data
def test_verify_read_semantics():
    o = os.OutcomeSupervision()
    rec = o.supervise("TASK-1", 1, outcome_verdict="accepted", task_digest=PIN)
    v = o.verify("sup-1", 0)
    assert v.verdict == "verified"
    assert v.integrity_ok is True
    assert v.verify()
    assert v.as_dict()["schema"] == os.SCHEMA_PIN
    with pytest.raises(os.UnknownSupervisionError):
        o.verify("sup-999", 0)
    # tamper -> reported as data, never raised
    object.__setattr__(rec, "outcome_verdict", "rejected")
    assert rec.verify() is False
    v2 = o.verify("sup-1", 0)
    assert v2.verdict == "tampered" and v2.integrity_ok is False
    assert v2.verify()
    e = o.evaluate("TASK-1", 0)
    assert e.integrity_ok is False  # ledger-rule: tamper flips the flag
    assert e.verify()


# 8. retire terminality + id non-recycling + bad reason + reads still work
def test_retire_terminality():
    o = os.OutcomeSupervision()
    o.supervise("TASK-1", 1, outcome_verdict="accepted")
    with pytest.raises(os.UnknownTaskError):
        o.retire("TASK-GHOST", 2)
    with pytest.raises(os.BadReasonError):
        o.retire("TASK-1", 3, reason="vibes")
    ret = o.retire("TASK-1", 4, reason="protocol-complete")
    assert ret.verify()
    assert ret.as_dict()["reason"] == "protocol-complete"
    with pytest.raises(os.RetiredTaskError):
        o.retire("TASK-1", 5)
    with pytest.raises(os.RetiredTaskError):
        o.supervise("TASK-1", 6)
    assert o.retired_ids(0) == ("TASK-1",)
    # reads still work post-retire
    assert o.evaluate("TASK-1", 0).posture == "accepted"
    assert o.verify("sup-1", 0).verdict == "verified"
    assert o.supervisions_for("TASK-1", 0) == ("sup-1",)


# 9. seq discipline: rewind bare, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    o = os.OutcomeSupervision()
    o.supervise("TASK-1", 5, outcome_verdict="accepted")
    with pytest.raises(os.SeqOrderError):
        o.supervise("TASK-2", 5)  # rewind: bare
    assert o.stats(6)["rejected"] == 0  # no row booked for bare rewind
    for bad in (True, 0, -1, 1.5, "2", None):
        with pytest.raises(os.SeqOrderError):
            o.supervise("TASK-2", bad)
    o.supervise("TASK-2", 7)
    assert o.task_ids(8) == ("TASK-1", "TASK-2")


# 10. view read-purity: same seq twice, no audit rows, no seq consumption
def test_view_read_purity():
    o = os.OutcomeSupervision()
    o.supervise("TASK-1", 1, supervision_kind="human-review", outcome_verdict="accepted", task_digest=PIN)
    n_audit = len(o.audit_log(3))
    e1 = o.evaluate("TASK-1", 3)
    e2 = o.evaluate("TASK-1", 3)
    assert e1.verify() and e2.verify()
    assert len(o.audit_log(3)) == n_audit  # reads add no rows
    assert o.task_ids(3) == ("TASK-1",)
    assert o.supervision_ids(3) == ("sup-1",)
    assert o.retired_ids(3) == ()
    assert o.supervision_record("sup-1", 3).verify()
    with pytest.raises(os.SeqOrderError):
        o.evaluate("TASK-1", -1)
    with pytest.raises(os.UnknownSupervisionError):
        o.supervision_record("sup-999", 3)


# 11. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    o = os.OutcomeSupervision()
    o.supervise("TASK-1", 1, supervision_kind="human-review", outcome_verdict="accepted", task_digest=PIN)
    o.retire("TASK-1", 2, reason="manual")
    rows = o.audit_log(3)
    assert [r["kind"] for r in rows] == ["supervised", "retired"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        for key in row["details"]:
            assert key not in os._BANNED_AUDIT_KEYS
    assert rows[0]["details"]["supervision_kind"] == "human-review"  # declared data allowed
    with pytest.raises(os.AuditKindError):
        os.outcome_supervision_audit_event("supervised", 1, transcript="leak")
    with pytest.raises(os.AuditKindError):
        os.outcome_supervision_audit_event("bogus-kind", 1)
    with pytest.raises(os.SeqOrderError):
        os.outcome_supervision_audit_event("supervised", -1)


# 12. cross-instance digest determinism + tamper breaks verify
def test_determinism_and_tamper():
    def build():
        o = os.OutcomeSupervision()
        o.supervise("TASK-1", 1, supervision_kind="model-judge", outcome_verdict="flagged", task_digest=PIN)
        return o

    o1, o2 = build(), build()
    assert o1.supervision_record("sup-1", 4).digest == o2.supervision_record("sup-1", 4).digest
    assert o1.evaluate("TASK-1", 4).digest == o2.evaluate("TASK-1", 4).digest
    rec = o1.supervision_record("sup-1", 4)
    tampered = dataclasses.replace(rec, outcome_verdict="accepted")
    assert tampered.verify() is False
    object.__setattr__(rec, "outcome_verdict", "accepted")
    assert rec.verify() is False
    assert o1.verify("sup-1", 4).integrity_ok is False


# 13. stats math
def test_stats():
    o = os.OutcomeSupervision()
    o.supervise("A", 1, outcome_verdict="accepted")
    o.supervise("B", 2, outcome_verdict="rejected")
    o.retire("B", 3)
    with pytest.raises(os.BadKindError):
        o.supervise("C", 4, supervision_kind="bad-kind")
    st = o.stats(5)
    assert st == {
        "tasks": 2,
        "supervisions": 2,
        "retired": 1,
        "rejected": 1,
        "audit_rows": 4,
        "seq": 4,  # failed mutation burned seq 4 (claim-then-burn)
    }


# 14. full lifecycle end to end + frozen-ness + thread smoke
def test_full_lifecycle_and_concurrency():
    o = os.OutcomeSupervision()
    o.supervise("LIFE", 1, supervision_kind="sampling-audit", outcome_verdict="flagged", task_digest=PIN)
    o.supervise("LIFE", 2, supervision_kind="human-review", outcome_verdict="accepted")
    e = o.evaluate("LIFE", 3)
    assert e.posture == "flagged" and e.n_supervisions == 2
    v = o.verify("sup-1", 3)
    assert v.verdict == "verified"
    rec = o.supervision_record("sup-1", 3)
    with pytest.raises(Exception):
        rec.task_digest = PIN  # frozen

    def worker():
        for _ in range(8):
            o.evaluate("LIFE", 4)
            o.verify("sup-1", 4)
            o.task_ids(4)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert o.evaluate("LIFE", 4).posture == "flagged"


# 15. main() subprocess check
def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        cwd=str(MOD.parent),
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "outcome-supervision OK: supervise, evaluate, verify, pins, audit"
    )
