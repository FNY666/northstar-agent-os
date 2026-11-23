"""Tests for the wireheading reward-channel detection ledger."""

import ast
import dataclasses
import pathlib
import subprocess
import sys
import threading

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import wireheading
from wireheading import (
    WIREHEADING_VERSION,
    SCHEMA_PIN,
    TAMPER_KINDS,
    DETECT_VERDICTS,
    RETIRE_REASONS,
    AUDIT_KINDS,
    AuditKindError,
    BadDigestError,
    BadIdError,
    BadReasonError,
    BadTamperKindError,
    BadVerdictError,
    DetectionRecord,
    EvaluationReport,
    RetireRecord,
    RetiredSystemError,
    SeqOrderError,
    UnknownDetectionError,
    UnknownSystemError,
    VerificationReport,
    Wireheading,
    wireheading_audit_event,
)

PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _new() -> Wireheading:
    return Wireheading()


# ---------------------------------------------------------------------------
# 1. version / schema pins
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert WIREHEADING_VERSION == "wireheading.v1"
    assert SCHEMA_PIN == "northstar.wireheading.v1"
    assert len(TAMPER_KINDS) == 8
    assert set(DETECT_VERDICTS) == {
        "confirmed",
        "suspect",
        "dismissed",
        "inconclusive",
    }
    assert set(RETIRE_REASONS) == {
        "manual",
        "superseded",
        "decommissioned",
        "false-start",
    }
    assert set(AUDIT_KINDS) == {"detected", "retired", "rejected"}


# ---------------------------------------------------------------------------
# 2. stdlib-only AST check
# ---------------------------------------------------------------------------


def test_stdlib_only_ast():
    assert Wireheading.stdlib_only() is True
    # Test-side independent walk with the house allowlist.
    allowed = {
        "__future__",
        "threading",
        "dataclasses",
        "hashlib",
        "json",
        "typing",
        "canonical_json",
        "ast",
        "pathlib",
    }
    tree = ast.parse(
        pathlib.Path(wireheading.__file__).read_text(encoding="utf-8")
    )
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] in allowed


# ---------------------------------------------------------------------------
# 3. detect roundtrip / minted ids / verify / frozen-ness
# ---------------------------------------------------------------------------


def test_detect_roundtrip_verify_frozen():
    wh = _new()
    rec = wh.detect(
        "sys-1",
        1,
        tamper_kind="reward-channel-tampering",
        verdict="confirmed",
        evidence_digest=PIN,
    )
    assert isinstance(rec, DetectionRecord)
    assert rec.detection_id == "det-1"
    assert rec.system_id == "sys-1"
    assert rec.tamper_kind == "reward-channel-tampering"
    assert rec.verdict == "confirmed"
    assert rec.evidence_digest == PIN
    assert rec.verify() is True
    assert rec.digest.startswith("sha256:")
    d = rec.as_dict()
    assert d["schema"] == SCHEMA_PIN
    # frozen-ness: plain setattr refused (object.__setattr__ bypasses and is
    # the intended test-side tamper path used elsewhere)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.tamper_kind = "sensor-spoofing"  # type: ignore


# ---------------------------------------------------------------------------
# 4. detect bad-input table + seq-burn + rejected-row accounting
# ---------------------------------------------------------------------------


def test_detect_bad_input_table_seq_burn():
    wh = _new()
    rows0 = len(wh.audit_log(1))
    bad = [
        # (system_id, tamper_kind, verdict, digest)
        ("", "reward-channel-tampering", "suspect", PIN),
        (None, "reward-channel-tampering", "suspect", PIN),
        ("sys-x" * 40, "reward-channel-tampering", "suspect", PIN),
        ("sys-1", "not-a-kind", "suspect", PIN),
        ("sys-1", None, "suspect", PIN),
        ("sys-1", "reward-channel-tampering", "not-a-verdict", PIN),
        ("sys-1", "reward-channel-tampering", "suspect", "nope"),
        ("sys-1", "reward-channel-tampering", "suspect", "sha256:" + "zz" * 32),
        ("sys-1", "reward-channel-tampering", "suspect", "sha256:" + "ab" * 31),
    ]
    rejected = 0
    for i, (sid, kind, verdict, digest) in enumerate(bad):
        seq = 10 + i
        exc = (BadIdError, BadTamperKindError, BadVerdictError, BadDigestError)
        with pytest.raises(exc):
            wh.detect(sid, seq, tamper_kind=kind, verdict=verdict,
                      evidence_digest=digest)
        rejected += 1
        # failed mutation consumed its seq: reuse must raise (seq not fresh)
        with pytest.raises(SeqOrderError):
            wh.detect("sys-1", seq, tamper_kind="sensor-spoofing",
                      verdict="suspect", evidence_digest=PIN)
    # rejected rows booked, counters incremented
    assert wh.stats(100)["rejected"] == rejected
    audit = wh.audit_log(101)
    rej = [r for r in audit if r["kind"] == "rejected"]
    assert len(rej) == rejected
    assert all(r["schema"] == "audit.ndjson/1" for r in rej)
    assert len(audit) == rows0 + rejected
    # no detections were booked
    assert wh.detection_ids(102) == ()


# ---------------------------------------------------------------------------
# 5. full 8-kind tamper vocabulary acceptance
# ---------------------------------------------------------------------------


def test_full_tamper_kind_vocabulary():
    wh = _new()
    seq = 1
    for i, kind in enumerate(TAMPER_KINDS):
        rec = wh.detect(
            f"sys-{i}",
            seq,
            tamper_kind=kind,
            verdict="suspect",
            evidence_digest=PIN,
        )
        assert rec.tamper_kind == kind
        assert rec.detection_id == f"det-{i + 1}"
        seq += 1
    assert len(wh.detection_ids(seq)) == 8


# ---------------------------------------------------------------------------
# 6. full verdict vocabulary acceptance
# ---------------------------------------------------------------------------


def test_full_verdict_vocabulary():
    wh = _new()
    seq = 1
    for i, verdict in enumerate(DETECT_VERDICTS):
        rec = wh.detect(
            "sys-1",
            seq,
            tamper_kind="reward-channel-tampering",
            verdict=verdict,
            evidence_digest=PIN,
        )
        assert rec.verdict == verdict
        seq += 1
    assert wh.detection_ids(seq) == ("det-1", "det-2", "det-3", "det-4")


# ---------------------------------------------------------------------------
# 7. retire terminality + id non-recycling + reads still work
# ---------------------------------------------------------------------------


def test_retire_terminality():
    wh = _new()
    wh.detect("sys-1", 1, tamper_kind="sensor-spoofing",
              verdict="confirmed", evidence_digest=PIN)
    # bad reason burns seq
    with pytest.raises(BadReasonError):
        wh.retire("sys-1", 2, reason="because")
    assert wh.stats(3)["rejected"] == 1
    rec = wh.retire("sys-1", 4, reason="decommissioned")
    assert isinstance(rec, RetireRecord)
    assert rec.verify() is True
    # double retire refused
    with pytest.raises(RetiredSystemError):
        wh.retire("sys-1", 5, reason="manual")
    # retired ids never recycled: new detections refused
    with pytest.raises(RetiredSystemError):
        wh.detect("sys-1", 6, tamper_kind="sensor-spoofing",
                  verdict="suspect", evidence_digest=PIN)
    assert wh.stats(7)["rejected"] == 3
    # post-retire reads still work
    assert wh.retired_ids(8) == ("sys-1",)
    rep = wh.evaluate("sys-1", 9)
    assert rep.posture == "compromised"
    # all four reasons accepted on fresh systems
    wh.detect("sys-2", 10, tamper_kind="sensor-spoofing",
              verdict="suspect", evidence_digest=PIN)
    for j, reason in enumerate(RETIRE_REASONS):
        sid = f"sys-r{j}"
        wh.detect(sid, 20 + j * 10, tamper_kind="sensor-spoofing",
                  verdict="suspect", evidence_digest=PIN)
        r = wh.retire(sid, 25 + j * 10, reason=reason)
        assert r.reason == reason
    # retire unknown system refused
    with pytest.raises(UnknownSystemError):
        wh.retire("sys-ghost", 80)
    assert wh.stats(81)["rejected"] == 4


# ---------------------------------------------------------------------------
# 8. evaluate posture math (all 4 postures + precedence)
# ---------------------------------------------------------------------------


def test_evaluate_posture_math():
    wh = _new()
    # dismissed-only -> clean
    wh.detect("clean-1", 1, tamper_kind="sensor-spoofing",
              verdict="dismissed", evidence_digest=PIN)
    rep = wh.evaluate("clean-1", 2)
    assert rep.verify() is True
    assert rep.posture == "clean"
    assert rep.n_detections == 1 and rep.n_dismissed == 1
    assert rep.integrity_ok is True
    # suspect -> suspect
    wh.detect("sus-1", 3, tamper_kind="sensor-spoofing",
              verdict="suspect", evidence_digest=PIN)
    rep = wh.evaluate("sus-1", 4)
    assert rep.posture == "suspect"
    # inconclusive alone -> suspect
    wh.detect("inc-1", 5, tamper_kind="sensor-spoofing",
              verdict="inconclusive", evidence_digest=PIN)
    rep = wh.evaluate("inc-1", 6)
    assert rep.posture == "suspect"
    # confirmed outranks suspect -> compromised
    wh.detect("mix-1", 7, tamper_kind="sensor-spoofing",
              verdict="suspect", evidence_digest=PIN)
    wh.detect("mix-1", 8, tamper_kind="reward-function-rewrite",
              verdict="confirmed", evidence_digest=PIN)
    rep = wh.evaluate("mix-1", 9)
    assert rep.posture == "compromised"
    assert rep.n_detections == 2 and rep.n_confirmed == 1
    assert rep.n_suspect == 1
    # evaluate unknown system refused (pure read: no burn, no rejected row)
    with pytest.raises(UnknownSystemError):
        wh.evaluate("sys-ghost", 10)
    assert wh.stats(11)["rejected"] == 0


# ---------------------------------------------------------------------------
# 9. evaluate / verify read purity (same seq twice, no audit rows)
# ---------------------------------------------------------------------------


def test_read_purity():
    wh = _new()
    wh.detect("sys-1", 1, tamper_kind="sensor-spoofing",
              verdict="confirmed", evidence_digest=PIN)
    rows0 = len(wh.audit_log(2))
    rep1 = wh.evaluate("sys-1", 3)
    rep2 = wh.evaluate("sys-1", 3)  # same seq again: allowed
    assert rep1 == rep2
    vrf1 = wh.verify("det-1", 4)
    vrf2 = wh.verify("det-1", 4)
    assert vrf1 == vrf2
    assert vrf1.verdict == "verified"
    assert vrf1.verify() is True
    rows1 = len(wh.audit_log(5))
    assert rows1 == rows0, "pure reads must not append audit rows"
    assert wh.stats(5)["rejected"] == 0
    # verify unknown id raises (pure read: no burn, no rejected row)
    with pytest.raises(UnknownDetectionError):
        wh.verify("det-999", 6)
    assert wh.stats(7)["rejected"] == 0


# ---------------------------------------------------------------------------
# 10. verify semantics + tamper reported as data
# ---------------------------------------------------------------------------


def test_verify_tamper_as_data():
    wh = _new()
    rec = wh.detect("sys-1", 1, tamper_kind="sensor-spoofing",
                    verdict="confirmed", evidence_digest=PIN)
    vrf = wh.verify("det-1", 2)
    assert vrf.verdict == "verified"
    assert vrf.integrity_ok is True
    # tamper the record in place: reported, never raised
    object.__setattr__(rec, "verdict", "dismissed")
    vrf2 = wh.verify("det-1", 3)
    assert vrf2.verdict == "tampered"
    assert vrf2.integrity_ok is False
    assert vrf2.verify() is True
    assert isinstance(vrf2, VerificationReport)
    # evaluate's integrity_ok flips as data too
    rep = wh.evaluate("sys-1", 4)
    assert rep.integrity_ok is False


# ---------------------------------------------------------------------------
# 11. seq discipline: rewind bare, malformed seqs, failed-mutation-consumes-seq
# ---------------------------------------------------------------------------


def test_seq_discipline():
    wh = _new()
    wh.detect("sys-1", 5, tamper_kind="sensor-spoofing",
              verdict="suspect", evidence_digest=PIN)
    rejected0 = wh.stats(6)["rejected"]
    # rewind raises bare: no audit row, rejected untouched
    with pytest.raises(SeqOrderError):
        wh.detect("sys-1", 5, tamper_kind="sensor-spoofing",
                  verdict="suspect", evidence_digest=PIN)
    with pytest.raises(SeqOrderError):
        wh.detect("sys-1", 1, tamper_kind="sensor-spoofing",
                  verdict="suspect", evidence_digest=PIN)
    assert wh.stats(7)["rejected"] == rejected0
    # malformed seqs raise without burning
    for bad_seq in (0, -1, True, "2", 2.5, None, (2,)):
        with pytest.raises(SeqOrderError):
            wh.detect("sys-1", bad_seq, tamper_kind="sensor-spoofing",
                      verdict="suspect", evidence_digest=PIN)
        with pytest.raises(SeqOrderError):
            wh.evaluate("sys-1", bad_seq)
        with pytest.raises(SeqOrderError):
            wh.verify("det-1", bad_seq)
    assert wh.stats(8)["rejected"] == rejected0
    # failed mutation consumes seq: same seq not reusable
    with pytest.raises(BadTamperKindError):
        wh.detect("sys-1", 20, tamper_kind="bogus",
                  verdict="suspect", evidence_digest=PIN)
    with pytest.raises(SeqOrderError):
        wh.detect("sys-1", 20, tamper_kind="sensor-spoofing",
                  verdict="suspect", evidence_digest=PIN)
    assert wh.stats(21)["rejected"] == rejected0 + 1


# ---------------------------------------------------------------------------
# 12. audit shapes + leak ban + bad kind
# ---------------------------------------------------------------------------


def test_audit_shapes_and_leak_ban():
    ev = wireheading_audit_event(
        "detected", 1, detection_id="det-1", system_id="sys-1",
        tamper_kind="sensor-spoofing", verdict="confirmed",
    )
    assert ev["schema"] == "audit.ndjson/1"
    assert ev["kind"] == "detected"
    assert ev["seq"] == 1
    # banned raw-material keys rejected at the builder
    for banned in ("weights", "policy", "reward", "gradient", "trajectory",
                   "sensor", "signal", "utility", "evidence"):
        with pytest.raises(AuditKindError):
            wireheading_audit_event("detected", 2, **{banned: "x"})
    # bad kind refused
    with pytest.raises(AuditKindError):
        wireheading_audit_event("probed", 3)
    # bad audit seq refused
    with pytest.raises(SeqOrderError):
        wireheading_audit_event("detected", -1)
    with pytest.raises(SeqOrderError):
        wireheading_audit_event("detected", True)
    # pinned vocabulary values remain emittable as declared data
    ev2 = wireheading_audit_event(
        "detected", 4, tamper_kind="value-function-hijack",
        verdict="confirmed",
    )
    assert ev2["details"]["tamper_kind"] == "value-function-hijack"
    # ledger audit rows carry only declared data
    wh = _new()
    wh.detect("sys-1", 1, tamper_kind="sensor-spoofing",
              verdict="confirmed", evidence_digest=PIN)
    (row,) = [r for r in wh.audit_log(2) if r["kind"] == "detected"]
    assert row["details"]["tamper_kind"] == "sensor-spoofing"
    assert set(row.keys()) == {"schema", "kind", "seq", "details"}


# ---------------------------------------------------------------------------
# 13. views + stats
# ---------------------------------------------------------------------------


def test_views_and_stats():
    wh = _new()
    wh.detect("sys-a", 1, tamper_kind="sensor-spoofing",
              verdict="suspect", evidence_digest=PIN)
    wh.detect("sys-a", 2, tamper_kind="reward-function-rewrite",
              verdict="dismissed", evidence_digest=PIN)
    wh.detect("sys-b", 3, tamper_kind="sensor-spoofing",
              verdict="suspect", evidence_digest=PIN)
    assert wh.system_ids(4) == ("sys-a", "sys-b")
    assert wh.detection_ids(5) == ("det-1", "det-2", "det-3")
    assert wh.detections_for("sys-a", 6) == ("det-1", "det-2")
    assert wh.detections_for("sys-b", 7) == ("det-3",)
    rec = wh.detection_record("det-2", 8)
    assert rec.verdict == "dismissed"
    with pytest.raises(UnknownDetectionError):
        wh.detection_record("det-999", 9)
    with pytest.raises(UnknownSystemError):
        wh.detections_for("sys-ghost", 10)
    assert wh.retired_ids(11) == ()
    wh.retire("sys-b", 12, reason="superseded")
    assert wh.retired_ids(13) == ("sys-b",)
    stats = wh.stats(14)
    # unknown-lookup reads raise without burning: rejected stays 0
    assert stats == {"systems": 2, "detections": 3, "retired": 1,
                     "rejected": 0}
    # evaluate returns a frozen report
    rep = wh.evaluate("sys-a", 15)
    assert isinstance(rep, EvaluationReport)
    assert rep.verify() is True
    with pytest.raises(dataclasses.FrozenInstanceError):
        rep.posture = "clean"  # type: ignore


# ---------------------------------------------------------------------------
# 14. cross-instance digest determinism
# ---------------------------------------------------------------------------


def test_cross_instance_digest_determinism():
    def build():
        wh = _new()
        wh.detect("sys-1", 1, tamper_kind="sensor-spoofing",
                  verdict="confirmed", evidence_digest=PIN)
        return wh

    a, b = build(), build()
    assert a.detection_record("det-1", 1).digest == \
        b.detection_record("det-1", 1).digest
    assert a.evaluate("sys-1", 2).digest == b.evaluate("sys-1", 2).digest
    assert a.verify("det-1", 3).digest == b.verify("det-1", 3).digest
    # different inputs -> different digests
    c = _new()
    c.detect("sys-1", 1, tamper_kind="sensor-spoofing",
             verdict="confirmed", evidence_digest=PIN2)
    assert c.detection_record("det-1", 1).digest != \
        a.detection_record("det-1", 1).digest


# ---------------------------------------------------------------------------
# 15. threaded read smoke + main() subprocess check
# ---------------------------------------------------------------------------


def test_threaded_read_smoke_and_main():
    wh = _new()
    wh.detect("sys-1", 1, tamper_kind="sensor-spoofing",
              verdict="confirmed", evidence_digest=PIN)
    errors = []

    def reader(n):
        try:
            for _ in range(50):
                rep = wh.evaluate("sys-1", 2 + n)
                assert rep.posture == "compromised"
                vrf = wh.verify("det-1", 2 + n)
                assert vrf.verdict == "verified"
                wh.stats(2 + n)
                wh.detection_ids(2 + n)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors

    proc = subprocess.run(
        [sys.executable, str(pathlib.Path(wireheading.__file__))],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "wireheading OK: detect, evaluate, verify, retire, pins, audit" in \
        proc.stdout
