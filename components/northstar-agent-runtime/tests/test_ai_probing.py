"""Tests for the AI-probing decision ledger, Simulated."""

import ast
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_probing.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32
PIN3 = "sha256:" + "ef" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_probing", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_probing"] = module
    spec.loader.exec_module(module)
    return module


ap = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert ap.AI_PROBING_VERSION == "ai-probing.v1"
    assert ap.SCHEMA_PIN == "northstar.ai-probing.v1"
    assert ap.PROBE_KINDS == (
        "linear-classifier",
        "concept-probe",
        "attention-probe",
        "layer-sweep",
        "sae-feature",
        "activation-patching",
        "logit-lens",
        "causal-intervention",
    )
    assert ap.FINDINGS == (
        "concept-detected",
        "concept-absent",
        "inconclusive",
        "not-run",
    )
    assert ap.VERIFY_OUTCOMES == (
        "confirmed",
        "overturned",
        "inconclusive",
    )
    assert ap.RETIRE_REASONS == (
        "manual",
        "superseded",
        "decommissioned",
        "false-start",
    )
    assert set(ap.AUDIT_KINDS) == {
        "probed",
        "verified",
        "retired",
        "rejected",
    }


# 2. stdlib-only AST self-check
def test_stdlib_only():
    tree = ast.parse(MOD.read_text())
    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "ast",
        "pathlib",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert node.module.split(".")[0] in allowed
    assert ap.stdlib_only() is True


# 3. probe roundtrip: prb-N minting, digest self-verification, frozenness
def test_probe_roundtrip():
    ledger = ap.AIProbing()
    rec = ledger.probe(
        "m1", "layer-7", 1, probe_kind="concept-probe",
        finding="concept-detected", probe_digest=PIN,
    )
    assert rec.probe_id == "prb-1"
    assert rec.model_id == "m1"
    assert rec.layer_id == "layer-7"
    assert rec.verify() is True
    assert rec.as_dict()["schema"] == "northstar.ai-probing.v1"
    import dataclasses

    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.finding = "concept-absent"  # frozen dataclasses reject mutation
    assert rec.finding == "concept-detected"  # still intact


# 4. bad-input table: seq burned + rejected row, rewinds raise bare
def test_probe_bad_inputs_burn_seq_and_book_rejected():
    ledger = ap.AIProbing()
    cases = [
        lambda s: ledger.probe("", "l1", s, probe_kind="linear-classifier", finding="concept-detected", probe_digest=PIN),
        lambda s: ledger.probe("m", "", s, probe_kind="linear-classifier", finding="concept-detected", probe_digest=PIN),
        lambda s: ledger.probe("m", "l1", s, probe_kind="nope", finding="concept-detected", probe_digest=PIN),
        lambda s: ledger.probe("m", "l1", s, probe_kind="linear-classifier", finding="nope", probe_digest=PIN),
        lambda s: ledger.probe("m", "l1", s, probe_kind="linear-classifier", finding="concept-detected", probe_digest="bad"),
        lambda s: ledger.probe("m", "l1", s, probe_kind="linear-classifier", finding="concept-detected", probe_digest="sha256:" + "zz" * 32),
        lambda s: ledger.probe("m", "l1", 0, probe_kind="linear-classifier", finding="concept-detected", probe_digest=PIN),
        lambda s: ledger.probe("m", "l1", True, probe_kind="linear-classifier", finding="concept-detected", probe_digest=PIN),
    ]
    seq = 1
    for fn in cases:
        with pytest.raises(ap.AIProbingError):
            fn(seq)
        seq += 1
    # the 6 malformed-input mutations consumed their seq and booked a
    # rejected row each; seq 0 and seq True raise bare at shape-check
    # (before the claim), burning nothing
    assert ledger.stats(seq)["rejected"] == 6
    audit = ledger.audit_log(seq + 1)
    assert all(row["kind"] == "rejected" for row in audit)
    assert len(audit) == 6
    # rewind of a valid seq raises bare (no new row)
    with pytest.raises(ap.SeqOrderError):
        ledger.probe("m", "l1", 1, probe_kind="linear-classifier", finding="concept-detected", probe_digest=PIN)
    assert ledger.stats(seq + 2)["rejected"] == 6


# 5. full probe-kind vocabulary accepted
def test_full_probe_kind_vocabulary():
    ledger = ap.AIProbing()
    for i, kind in enumerate(ap.PROBE_KINDS):
        rec = ledger.probe(
            "m", f"layer-{i}", i + 1, probe_kind=kind,
            finding="not-run", probe_digest=PIN,
        )
        assert rec.probe_id == f"prb-{i + 1}"
        assert rec.probe_kind == kind
        assert rec.verify() is True


# 6. full finding vocabulary + verify roundtrip + ver-N minting
def test_full_finding_vocabulary_and_verify():
    ledger = ap.AIProbing()
    for i, finding in enumerate(ap.FINDINGS):
        rec = ledger.probe(
            "m", f"layer-{i}", i + 1, probe_kind="logit-lens",
            finding=finding, probe_digest=PIN,
        )
        assert rec.probe_id == f"prb-{i + 1}"
    for i, finding in enumerate(ap.FINDINGS):
        ver = ledger.verify(
            f"prb-{i + 1}", 10 + i, outcome="confirmed", review_digest=PIN2,
        )
        assert ver.verification_id == f"ver-{i + 1}"
        assert ver.verify() is True
        assert ledger.verification_for(f"prb-{i + 1}", 50 + i) == f"ver-{i + 1}"


# 7. verify refusal table: unknown probe, bad outcome, bad digest, double
def test_verify_refusals():
    ledger = ap.AIProbing()
    rec = ledger.probe("m", "l1", 1, probe_kind="sae-feature",
                       finding="inconclusive", probe_digest=PIN)
    with pytest.raises(ap.UnknownProbeError):
        ledger.verify("prb-999", 2, outcome="confirmed", review_digest=PIN2)
    with pytest.raises(ap.BadOutcomeError):
        ledger.verify(rec.probe_id, 3, outcome="nope", review_digest=PIN2)
    with pytest.raises(ap.BadDigestError):
        ledger.verify(rec.probe_id, 4, outcome="confirmed", review_digest="bad")
    ledger.verify(rec.probe_id, 5, outcome="overturned", review_digest=PIN2)
    with pytest.raises(ap.AlreadyVerifiedError):
        ledger.verify(rec.probe_id, 6, outcome="confirmed", review_digest=PIN2)
    assert ledger.stats(7)["rejected"] == 4


# 8. verify semantics: tamper-as-data, read purity, unknown refusal
def test_verify_semantics():
    ledger = ap.AIProbing()
    rec = ledger.probe("m", "l1", 1, probe_kind="activation-patching",
                       finding="concept-detected", probe_digest=PIN)
    n_before = len(ledger.audit_log(2))
    got = ledger.probe_record(rec.probe_id, 3)
    assert got == rec
    assert len(ledger.audit_log(4)) == n_before  # reads add no rows
    # tamper is reported as data, never raised
    object.__setattr__(rec, "digest", "sha256:" + "00" * 32)
    assert rec.verify() is False
    ev = ledger.evaluate("m", 5)
    assert ev.integrity_ok is False
    with pytest.raises(ap.UnknownProbeError):
        ledger.probe_record("prb-999", 6)


# 9. evaluate tally math: all findings + verifications
def test_evaluate_tally_math():
    ledger = ap.AIProbing()
    seq = 1
    for kind, finding in zip(
        ("linear-classifier", "concept-probe", "logit-lens", "sae-feature"),
        ("concept-detected", "concept-absent", "inconclusive", "not-run"),
    ):
        ledger.probe("m", "l", seq, probe_kind=kind, finding=finding, probe_digest=PIN)
        seq += 1
    ledger.verify("prb-1", seq, outcome="confirmed", review_digest=PIN2)
    seq += 1
    ledger.verify("prb-2", seq, outcome="overturned", review_digest=PIN2)
    seq += 1
    ev = ledger.evaluate("m", seq)
    assert ev.n_probes == 4
    assert ev.n_detected == 1
    assert ev.n_absent == 1
    assert ev.n_inconclusive == 2
    assert ev.n_verified == 2
    assert ev.n_confirmed == 1
    assert ev.n_overturned == 1
    assert ev.integrity_ok is True
    assert ev.verify() is True
    with pytest.raises(ap.UnknownModelError):
        ledger.evaluate("unknown-model", seq + 1)


# 10. retire terminality: bad reason, double-retire, no recycle, reads work
def test_retire_terminality():
    ledger = ap.AIProbing()
    ledger.probe("m", "l", 1, finding="not-run", probe_digest=PIN)
    with pytest.raises(ap.BadReasonError):
        ledger.retire("m", 2, reason="nope")
    ret = ledger.retire("m", 3, reason="manual")
    assert ret.verify() is True
    assert ledger.retired_ids(4) == ("m",)
    with pytest.raises(ap.RetiredModelError):
        ledger.retire("m", 5, reason="manual")
    with pytest.raises(ap.RetiredModelError):
        ledger.probe("m", "l", 6, finding="not-run", probe_digest=PIN)
    # post-retire reads still work
    ev = ledger.evaluate("m", 7)
    assert ev.n_probes == 1
    assert ledger.probes_for("m", 8) == ("prb-1",)
    assert ledger.stats(9)["rejected"] == 3


# 11. seq discipline: genesis rewind bare, malformed seqs, burn accounting
def test_seq_discipline():
    ledger = ap.AIProbing()
    with pytest.raises(ap.SeqOrderError):  # seq must be positive
        ledger.probe("m", "l", 0, finding="not-run", probe_digest=PIN)
    with pytest.raises(ap.SeqOrderError):
        ledger.probe("m", "l", -1, finding="not-run", probe_digest=PIN)
    with pytest.raises(ap.SeqOrderError):
        ledger.probe("m", "l", "1", finding="not-run", probe_digest=PIN)
    ledger.probe("m", "l", 1, finding="not-run", probe_digest=PIN)
    with pytest.raises(ap.SeqOrderError):  # rewind raises bare, burns nothing
        ledger.probe("m", "l", 1, finding="not-run", probe_digest=PIN)
    assert ledger.stats(2)["rejected"] == 0
    assert len(ledger.audit_log(3)) == 1  # only the successful probe row


# 12. audit shapes + leak ban + bad kind
def test_audit_shapes_and_leak_ban():
    ledger = ap.AIProbing()
    rec = ledger.probe("m", "l", 1, probe_kind="causal-intervention",
                       finding="concept-absent", probe_digest=PIN)
    rows = ledger.audit_log(2)
    assert rows[0]["schema"] == "audit.ndjson/1"
    assert rows[0]["kind"] == "probed"
    assert rows[0]["details"]["probe_id"] == rec.probe_id
    assert rows[0]["details"]["probe_kind"] == "causal-intervention"
    with pytest.raises(ap.AuditKindError):
        ap.ai_probing_audit_event("probed", 1, activations=b"raw")
    with pytest.raises(ap.AuditKindError):
        ap.ai_probing_audit_event("probed", 1, embeddings="raw")
    with pytest.raises(ap.AuditKindError):
        ap.ai_probing_audit_event("probed", 1, probe_data={"x": 1})
    with pytest.raises(ap.AuditKindError):
        ap.ai_probing_audit_event("nope", 1, probe_id="prb-1")


# 13. views, stats, unknown lookups
def test_views_and_stats():
    ledger = ap.AIProbing()
    ledger.probe("m1", "l1", 1, finding="concept-detected", probe_digest=PIN)
    ledger.probe("m2", "l2", 2, finding="concept-absent", probe_digest=PIN)
    ledger.verify("prb-1", 3, outcome="confirmed", review_digest=PIN2)
    assert ledger.model_ids(4) == ("m1", "m2")
    assert ledger.probe_ids(5) == ("prb-1", "prb-2")
    assert ledger.verification_ids(6) == ("ver-1",)
    assert ledger.probes_for("m1", 7) == ("prb-1",)
    assert ledger.probes_for("m2", 8) == ("prb-2",)
    assert ledger.verifications_for("m1", 9) == ("ver-1",)
    assert ledger.verifications_for("m2", 10) == ()
    assert ledger.stats(11) == {
        "models": 2,
        "probes": 2,
        "verifications": 1,
        "retired": 0,
        "rejected": 0,
    }
    with pytest.raises(ap.UnknownModelError):
        ledger.probes_for("nope", 12)
    with pytest.raises(ap.UnknownModelError):
        ledger.retire("nope", 13)


# 14. cross-instance digest determinism + thread read smoke
def test_determinism_and_thread_safety():
    a = ap.AIProbing()
    b = ap.AIProbing()
    ra = a.probe("m", "l", 1, probe_kind="layer-sweep",
                 finding="inconclusive", probe_digest=PIN)
    rb = b.probe("m", "l", 1, probe_kind="layer-sweep",
                 finding="inconclusive", probe_digest=PIN)
    assert ra.digest == rb.digest  # same inputs -> same pin across instances

    errs = []

    def reader():
        try:
            for _ in range(50):
                a.evaluate("m", 2)
                a.stats(2)
                a.probe_ids(2)
        except Exception as exc:  # noqa: BLE001
            errs.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errs == []


# 15. main() self-check via subprocess
def test_main_self_check():
    import subprocess

    out = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert out.returncode == 0
    assert "ai-probing OK: probe, verify, evaluate, retire, pins, audit" in out.stdout
