"""Tests for the GPAI governance decision ledger, Simulated."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "gpai.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32
PIN3 = "sha256:" + "ef" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("gpai", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["gpai"] = module
    spec.loader.exec_module(module)
    return module


gp = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert gp.GPAI_VERSION == "gpai.v1"
    assert gp.SCHEMA_PIN == "northstar.gpai.v1"
    assert gp.CATEGORIES == (
        "not-gpai",
        "gpai",
        "gpai-systemic-risk",
    )
    assert gp.EVAL_KINDS == (
        "capability",
        "adversarial-robustness",
        "red-team",
        "systemic-risk",
        "benchmark",
    )
    assert gp.EVAL_OUTCOMES == (
        "pass",
        "fail",
        "inconclusive",
    )
    assert gp.NOTIFICATIONS == (
        "ai-office-filing",
        "downstream-info",
        "incident-report",
        "serious-incident",
    )
    assert gp.RETIRE_REASONS == (
        "manual",
        "superseded",
        "decommissioned",
    )
    assert set(gp.AUDIT_KINDS) == {
        "classified",
        "evaluated",
        "notified",
        "retired",
        "rejected",
    }


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
    }
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    assert imports <= allowed, f"non-stdlib imports: {imports - allowed}"


# 3. classify roundtrip + verify()
def test_classify_roundtrip_and_verify():
    g = gp.GPAI()
    rec = g.classify("model-a", 1, category="gpai", model_digest=PIN)
    assert rec.model_id == "model-a"
    assert rec.category == "gpai"
    assert rec.model_digest == PIN
    assert rec.verify()
    assert rec.as_dict()["schema"] == "northstar.gpai.v1"
    fetched = g.classification_record("model-a", 2)
    assert fetched == rec
    assert g.model_ids(3) == ("model-a",)


# 4. classify bad-input table + duplicate + seq-burn + rejected rows
def test_classify_bad_inputs_and_duplicate():
    g = gp.GPAI()
    seq = 1
    bad = [
        ("", "not-gpai", PIN),
        ("x" * 129, "not-gpai", PIN),
        (None, "not-gpai", PIN),
        ("ok-1", "not-a-category", PIN),
        ("ok-1", "gpai", "raw-not-a-pin"),
        ("ok-1", "gpai", "sha256:" + "zz" * 32),
        ("ok-1", "gpai", ""),
        ("ok-1", 123, PIN),
    ]
    n_rejected = 0
    for mid, cat, pin in bad:
        with pytest.raises(gp.GPAIError):
            g.classify(mid, seq, category=cat, model_digest=pin)
        seq += 1
        n_rejected += 1
    g.classify("dup", seq, category="gpai", model_digest=PIN)
    seq += 1
    with pytest.raises(gp.DuplicateModelError):
        g.classify("dup", seq, category="gpai", model_digest=PIN)
    n_rejected += 1
    stats = g.stats(seq + 1)
    assert stats["rejected"] == n_rejected
    rows = g.audit_log(seq + 2)
    rejected_rows = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected_rows) == n_rejected


# 5. full category vocabulary acceptance
def test_classify_full_category_vocabulary():
    g = gp.GPAI()
    seq = 1
    for i, cat in enumerate(gp.CATEGORIES):
        rec = g.classify(f"m-{i}", seq, category=cat, model_digest=PIN)
        assert rec.category == cat
        assert rec.verify()
        seq += 1


# 6. evaluate roundtrip + minted ids + verify()
def test_evaluate_roundtrip_and_minted_ids():
    g = gp.GPAI()
    g.classify("model-b", 1, category="gpai-systemic-risk", model_digest=PIN)
    ev1 = g.evaluate(
        "model-b", 2, eval_kind="systemic-risk", outcome="pass", report_digest=PIN
    )
    assert ev1.eval_id == "eval-1"
    assert ev1.verify()
    ev2 = g.evaluate(
        "model-b", 3, eval_kind="red-team", outcome="inconclusive", report_digest=PIN2
    )
    assert ev2.eval_id == "eval-2"
    assert g.evaluation_record("eval-1", 4) == ev1
    assert g.evaluations_for("model-b", 5) == ("eval-1", "eval-2")
    assert g.status(6).n_evaluations == 2


# 7. evaluate bad-input table + seq-burn
def test_evaluate_bad_inputs():
    g = gp.GPAI()
    g.classify("model-c", 1, category="gpai", model_digest=PIN)
    seq = 2
    bad = [
        ("unknown-model", "capability", "pass", PIN),
        ("model-c", "not-a-kind", "pass", PIN),
        ("model-c", "capability", "not-an-outcome", PIN),
        ("model-c", "capability", "pass", "raw"),
        ("model-c", "capability", "pass", ""),
        (None, "capability", "pass", PIN),
    ]
    n_rejected = 0
    for mid, kind, outcome, pin in bad:
        with pytest.raises(gp.GPAIError):
            g.evaluate(mid, seq, eval_kind=kind, outcome=outcome, report_digest=pin)
        seq += 1
        n_rejected += 1
    assert g.stats(seq)["rejected"] == n_rejected


# 8. evaluate on retired model refused
def test_evaluate_refused_on_retired_model():
    g = gp.GPAI()
    g.classify("model-r", 1, category="gpai", model_digest=PIN)
    g.retire("model-r", 2, reason="decommissioned")
    with pytest.raises(gp.RetiredModelError):
        g.evaluate("model-r", 3, eval_kind="capability", outcome="pass", report_digest=PIN)


# 9. notify roundtrip + minted ids + verify()
def test_notify_roundtrip_and_minted_ids():
    g = gp.GPAI()
    g.classify("model-d", 1, category="gpai-systemic-risk", model_digest=PIN)
    n1 = g.notify(
        "model-d", 2, notification="ai-office-filing", reference_digest=PIN
    )
    assert n1.notification_id == "ntf-1"
    assert n1.verify()
    n2 = g.notify(
        "model-d", 3, notification="serious-incident", reference_digest=PIN2
    )
    assert n2.notification_id == "ntf-2"
    assert g.notification_record("ntf-1", 4) == n1
    assert g.notifications_for("model-d", 5) == ("ntf-1", "ntf-2")
    with pytest.raises(gp.UnknownNotificationError):
        g.notification_record("ntf-999", 6)


# 10. notify bad-input table + seq-burn
def test_notify_bad_inputs():
    g = gp.GPAI()
    g.classify("model-e", 1, category="gpai", model_digest=PIN)
    seq = 2
    bad = [
        ("unknown-model", "ai-office-filing", PIN),
        ("model-e", "not-a-notification", PIN),
        ("model-e", "ai-office-filing", "raw"),
        ("model-e", "ai-office-filing", ""),
        ("model-e", 123, PIN),
    ]
    n_rejected = 0
    for mid, notif, pin in bad:
        with pytest.raises(gp.GPAIError):
            g.notify(mid, seq, notification=notif, reference_digest=pin)
        seq += 1
        n_rejected += 1
    assert g.stats(seq)["rejected"] == n_rejected


# 11. retire terminality
def test_retire_terminality():
    g = gp.GPAI()
    g.classify("model-f", 1, category="gpai", model_digest=PIN)
    rec = g.retire("model-f", 2, reason="superseded")
    assert rec.verify()
    assert g.retired_ids(3) == ("model-f",)
    # double-retire refused
    with pytest.raises(gp.RetiredModelError):
        g.retire("model-f", 4, reason="manual")
    # id never recycled
    with pytest.raises(gp.RetiredModelError):
        g.classify("model-f", 5, category="not-gpai", model_digest=PIN)
    # notify on retired refused
    with pytest.raises(gp.RetiredModelError):
        g.notify("model-f", 6, notification="incident-report", reference_digest=PIN)
    # reads still work after retire
    assert g.classification_record("model-f", 7).category == "gpai"
    # bad reason refused
    g.classify("model-g", 8, category="gpai", model_digest=PIN)
    with pytest.raises(gp.BadReasonError):
        g.retire("model-g", 9, reason="nope")


# 12. seq discipline
def test_seq_discipline():
    g = gp.GPAI()
    g.classify("model-s", 1, category="gpai", model_digest=PIN)
    # rewind raises bare, consumes nothing, books nothing
    n_before = len(g.audit_log(2))
    with pytest.raises(gp.SeqOrderError):
        g.classify("model-s2", 1, category="gpai", model_digest=PIN)
    assert len(g.audit_log(3)) == n_before
    assert g.stats(4)["rejected"] == 0
    # malformed seqs raise bare
    for bad_seq in (0, -1, True, "1", 1.5, None):
        with pytest.raises(gp.SeqOrderError):
            g.classify("model-x", bad_seq, category="gpai", model_digest=PIN)
    # failed mutation consumes seq and burns
    with pytest.raises(gp.DuplicateModelError):
        g.classify("model-s", 5, category="gpai", model_digest=PIN)
    assert g.stats(6)["rejected"] == 1
    # rewinds are bare: seq 5 was consumed
    with pytest.raises(gp.SeqOrderError):
        g.classify("model-new", 5, category="gpai", model_digest=PIN)


# 13. view read-purity
def test_view_read_purity():
    g = gp.GPAI()
    g.classify("model-v", 1, category="gpai", model_digest=PIN)
    g.evaluate("model-v", 2, eval_kind="capability", outcome="pass", report_digest=PIN)
    g.notify("model-v", 3, notification="downstream-info", reference_digest=PIN)
    n_before = len(g.audit_log(4))
    # same-seq reads twice, no audit rows, seq not consumed
    assert g.status(5).n_models == 1
    assert g.status(5).n_evaluations == 1
    assert g.status(5).n_notifications == 1
    assert len(g.audit_log(6)) == n_before
    # unknown lookups raise
    with pytest.raises(gp.UnknownModelError):
        g.classification_record("nope", 7)
    with pytest.raises(gp.UnknownEvaluationError):
        g.evaluation_record("eval-999", 8)
    assert g.evaluations_for("model-v", 9) == ("eval-1",)
    assert g.notifications_for("model-v", 10) == ("ntf-1",)
    # retire records are verifiable
    g.retire("model-v", 11, reason="manual")
    assert g.stats(12)["retired"] == 1


# 14. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    g = gp.GPAI()
    g.classify("model-a", 1, category="gpai", model_digest=PIN)
    g.evaluate("model-a", 2, eval_kind="benchmark", outcome="fail", report_digest=PIN)
    g.notify("model-a", 3, notification="incident-report", reference_digest=PIN)
    g.retire("model-a", 4, reason="manual")
    rows = g.audit_log(5)
    kinds = [r["kind"] for r in rows]
    assert kinds == ["classified", "evaluated", "notified", "retired"]
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
    # banned keys refused at the builder
    with pytest.raises(gp.AuditKindError):
        gp.gpai_audit_event("classified", 0, weights="raw-weights")
    with pytest.raises(gp.AuditKindError):
        gp.gpai_audit_event("evaluated", 0, score=0.99)
    with pytest.raises(gp.AuditKindError):
        gp.gpai_audit_event("notified", 0, filing="raw-filing")
    # bad kind refused
    with pytest.raises(gp.AuditKindError):
        gp.gpai_audit_event("bogus-kind", 0)
    # no banned raw keys in any row detail
    banned = gp._BANNED_AUDIT_KEYS
    for r in rows:
        for key in r["details"]:
            assert key not in banned


# 15. digest determinism + tamper + frozen-ness + threads + main()
def test_digest_determinism_tamper_and_main():
    g1 = gp.GPAI()
    g2 = gp.GPAI()
    r1 = g1.classify("model-z", 1, category="gpai-systemic-risk", model_digest=PIN)
    r2 = g2.classify("model-z", 1, category="gpai-systemic-risk", model_digest=PIN)
    assert r1.digest == r2.digest
    # tamper breaks verify()
    import dataclasses

    assert r1.verify()
    object.__setattr__(r1, "category", "not-gpai")
    assert not r1.verify()
    # status flags integrity as data
    st = g1.status(2)
    assert st.integrity_ok is False
    assert st.verify()
    # frozen records reject attribute assignment
    with pytest.raises(dataclasses.FrozenInstanceError):
        r2.model_id = "mutated"
    # concurrent reads are safe
    errors = []

    def reader():
        try:
            g1.classification_record("model-z", 3)
            g1.status(4)
            g1.stats(5)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    # main() self-check
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        cwd=MOD.parent,
        timeout=60,
    )
    assert proc.returncode == 0
    assert "gpai OK: classify, evaluate, notify, retire, pins, audit" in proc.stdout
