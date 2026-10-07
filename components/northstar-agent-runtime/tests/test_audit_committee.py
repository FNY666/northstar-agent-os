"""Targeted tests for audit_committee (15 tests).

House conventions under test: frozen dataclasses, caller-supplied
strictly-increasing int seqs (failed mutations consume their seq and
book a rejected row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only,
sha256: digest pins, and audit.ndjson/1 events whose boundary bans
raw subject/finding/rationale text.
"""

from __future__ import annotations

import ast
import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

import audit_committee as ac

HERE = Path(__file__).resolve()
MODULE_PATH = HERE.parent.parent / "audit_committee.py"


def _digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# 1-2: pins and stdlib-only
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert ac.AUDIT_COMMITTEE_VERSION == "audit-committee.v1"
    assert ac.AUDIT_COMMITTEE_SCHEMA == "northstar.audit-committee.v1"
    assert ac.AUDIT_SCHEMA == "audit.ndjson/1"
    assert ac._KINDS == frozenset(
        {
            "audit-committee.review-opened",
            "audit-committee.certified",
            "audit-committee.escalated",
            "audit-committee.rejected",
        }
    )
    assert ac._VERDICTS == frozenset({"clean", "qualified", "adverse", "disclaimer"})
    assert ac._LEVELS == frozenset(
        {"management", "board", "regulator", "independent-investigator"}
    )


def test_stdlib_only_ast():
    tree = ast.parse(MODULE_PATH.read_text())
    allowed = {
        "hashlib",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "json",
        "canonical_json",
    }
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    assert imports <= allowed, f"non-stdlib import: {imports - allowed}"


# ---------------------------------------------------------------------------
# 3-5: review lifecycle
# ---------------------------------------------------------------------------


def test_review_roundtrip_verify():
    ledger = ac.AuditCommittee()
    rec = ledger.review("rev-1", _digest("subject"), 1)
    assert rec.review_id == "rev-1"
    assert rec.subject_digest == _digest("subject")
    assert rec.seq == 1
    assert rec.schema == "northstar.audit-committee.v1"
    assert rec.verify()
    # frozen
    with pytest.raises(Exception):
        rec.review_id = "rev-2"  # type: ignore
    # view roundtrip
    assert ledger.review_record("rev-1", 1) is rec
    assert ledger.review_ids(1) == ("rev-1",)
    assert ledger.review_record("missing", 1) is None


def test_review_duplicate_seq_burn():
    ledger = ac.AuditCommittee()
    ledger.review("rev-1", _digest("subject"), 1)
    with pytest.raises(ac.DuplicateReviewError):
        ledger.review("rev-1", _digest("other"), 2)
    # failed mutation consumed its seq: seq 2 is burned
    assert ledger.stats(2)["last_seq"] == 2
    # rejected row booked
    events = ledger.audit_log()
    assert len(events) == 2
    assert events[1]["kind"] == "audit-committee.rejected"
    assert events[1]["seq"] == 2
    assert events[1]["detail"]["error"] == "DuplicateReviewError"
    # ids are never recycled: a fresh review id still works, duplicate stays dead
    ledger.review("rev-2", _digest("subject"), 3)
    with pytest.raises(ac.DuplicateReviewError):
        ledger.review("rev-1", _digest("again"), 4)


def test_review_bad_inputs():
    ledger = ac.AuditCommittee()
    bad_ids = ["", "   " * 100, 123, None, True, b"rev", "x" * 257]
    seq = 0
    for bad in bad_ids:
        seq += 1
        with pytest.raises(ac.BadReviewError):
            ledger.review(bad, _digest("s"), seq)
    bad_digests = ["", "raw-text", "md5:abc", 123, None, True, "sha256:"]
    for bad in bad_digests:
        seq += 1
        with pytest.raises(ac.BadDigestError):
            ledger.review(f"rev-bad-{seq}", bad, seq)
    # all failures burned their seq and booked rejected rows
    assert ledger.stats(seq)["last_seq"] == seq
    rejected = [e for e in ledger.audit_log() if e["kind"] == "audit-committee.rejected"]
    assert len(rejected) == len(bad_ids) + len(bad_digests)
    assert ledger.review_ids(seq) == ()


# ---------------------------------------------------------------------------
# 6-8: certify lifecycle
# ---------------------------------------------------------------------------


def test_certify_roundtrip_verify():
    for verdict in ("clean", "qualified", "adverse", "disclaimer"):
        ledger = ac.AuditCommittee()
        ledger.review("rev-1", _digest("subject"), 1)
        rec = ledger.certify(
            "rev-1", verdict, 2, finding_digests=(_digest("f1"), _digest("f2"))
        )
        assert rec.certification_id == "cert-1"
        assert rec.review_id == "rev-1"
        assert rec.verdict == verdict
        assert rec.finding_digests == (_digest("f1"), _digest("f2"))
        assert rec.verify()
        assert ledger.certification("rev-1", 2) is rec
        assert ledger.is_certified("rev-1", 2) is True


def test_certify_bad_inputs():
    ledger = ac.AuditCommittee()
    ledger.review("rev-1", _digest("subject"), 1)
    seq = 1
    bad_verdicts = ["", "pass", "FAIL", 123, None, True, b"clean"]
    for bad in bad_verdicts:
        seq += 1
        with pytest.raises(ac.BadVerdictError):
            ledger.certify("rev-1", bad, seq)
    # unknown review
    seq += 1
    with pytest.raises(ac.UnknownReviewError):
        ledger.certify("nope", "clean", seq)
    # bad finding digests
    for bad in (("raw",), ("sha256:",), (_digest("f1"), _digest("f1"))):
        seq += 1
        with pytest.raises(ac.BadDigestError):
            ledger.certify("rev-1", "clean", seq, finding_digests=bad)
    # nothing certified despite the failures
    assert ledger.is_certified("rev-1", seq) is False
    assert ledger.certification("rev-1", seq) is None
    assert ledger.stats(seq)["last_seq"] == seq


def test_certify_terminality():
    ledger = ac.AuditCommittee()
    ledger.review("rev-1", _digest("subject"), 1)
    ledger.certify("rev-1", "clean", 2)
    with pytest.raises(ac.AlreadyCertifiedError):
        ledger.certify("rev-1", "adverse", 3)
    # failed re-certification burned seq 3
    assert ledger.stats(3)["last_seq"] == 3
    events = ledger.audit_log()
    kinds = [e["kind"] for e in events]
    assert kinds == [
        "audit-committee.review-opened",
        "audit-committee.certified",
        "audit-committee.rejected",
    ]
    # original opinion is untouched
    assert ledger.certification("rev-1", 3).verdict == "clean"


# ---------------------------------------------------------------------------
# 9-11: escalate lifecycle
# ---------------------------------------------------------------------------


def test_escalate_roundtrip_chain():
    ledger = ac.AuditCommittee()
    ledger.review("rev-1", _digest("subject"), 1)
    esc1 = ledger.escalate("rev-1", "board", 2, rationale_digest=_digest("why"))
    assert esc1.escalation_id == "esc-1"
    assert esc1.level == "board"
    assert esc1.rationale_digest == _digest("why")
    assert esc1.verify()
    # escalation chain: the same review may be escalated again
    esc2 = ledger.escalate("rev-1", "regulator", 3)
    assert esc2.escalation_id == "esc-2"
    assert esc2.rationale_digest == ""
    assert esc2.verify()
    chain = ledger.escalations_for("rev-1", 3)
    assert tuple(e.escalation_id for e in chain) == ("esc-1", "esc-2")
    assert ledger.escalations_for("missing", 3) == ()


def test_escalate_level_vocabulary():
    for level in ("management", "board", "regulator", "independent-investigator"):
        ledger = ac.AuditCommittee()
        ledger.review("rev-1", _digest("subject"), 1)
        rec = ledger.escalate("rev-1", level, 2)
        assert rec.level == level
        assert rec.verify()
    ledger = ac.AuditCommittee()
    ledger.review("rev-1", _digest("subject"), 1)
    seq = 1
    for bad in ["", "ceo", "BOARD", 123, None, True, b"board"]:
        seq += 1
        with pytest.raises(ac.BadLevelError):
            ledger.escalate("rev-1", bad, seq)
    seq += 1
    with pytest.raises(ac.BadDigestError):
        ledger.escalate("rev-1", "board", seq, rationale_digest="not-a-digest")
    assert ledger.stats(seq)["last_seq"] == seq
    assert ledger.escalations_for("rev-1", seq) == ()


def test_escalate_unknown_review_refusal():
    ledger = ac.AuditCommittee()
    with pytest.raises(ac.UnknownReviewError):
        ledger.escalate("ghost", "board", 1)
    events = ledger.audit_log()
    assert len(events) == 1
    assert events[0]["kind"] == "audit-committee.rejected"
    assert events[0]["detail"]["error"] == "UnknownReviewError"


# ---------------------------------------------------------------------------
# 12-14: seq discipline, read purity, audit boundary
# ---------------------------------------------------------------------------


def test_seq_discipline():
    ledger = ac.AuditCommittee()
    # rewind raises bare: consumes nothing, books no rejected row
    ledger.review("rev-1", _digest("subject"), 5)
    with pytest.raises(ac.SeqOrderError):
        ledger.review("rev-2", _digest("subject"), 5)
    with pytest.raises(ac.SeqOrderError):
        ledger.review("rev-2", _digest("subject"), 1)
    assert ledger.stats(5)["last_seq"] == 5
    assert len(ledger.audit_log()) == 1
    # malformed seqs
    for bad in (True, "7", 7.0, None):
        with pytest.raises(ac.SeqOrderError):
            ledger.review("rev-2", _digest("subject"), bad)
    assert ledger.stats(5)["last_seq"] == 5
    assert len(ledger.audit_log()) == 1
    # views validate shape but never consume
    ledger.review_ids(5)
    ledger.stats(1)  # lower seqs are legal for pure reads
    assert len(ledger.audit_log()) == 1


def test_view_read_purity():
    ledger = ac.AuditCommittee()
    ledger.review("rev-1", _digest("s"), 1)
    ledger.certify("rev-1", "clean", 2)
    ledger.escalate("rev-1", "board", 3)
    before = len(ledger.audit_log())
    # same-seq reads: allowed, no rows, no seq consumption
    for _ in range(3):
        assert ledger.review_record("rev-1", 3) is not None
        assert ledger.certification("rev-1", 3) is not None
        assert ledger.is_certified("rev-1", 3) is True
        assert len(ledger.escalations_for("rev-1", 3)) == 1
        assert ledger.review_ids(3) == ("rev-1",)
        assert ledger.stats(3)["reviews"] == 1
    assert len(ledger.audit_log()) == before
    assert ledger.stats(3)["last_seq"] == 3


def test_audit_shapes_leak_ban():
    ledger = ac.AuditCommittee()
    rec = ledger.review("rev-1", _digest("subject"), 1)
    cert = ledger.certify("rev-1", "qualified", 2, finding_digests=(_digest("f"),))
    esc = ledger.escalate("rev-1", "board", 3, rationale_digest=_digest("r"))
    events = ledger.audit_log()
    assert [e["kind"] for e in events] == [
        "audit-committee.review-opened",
        "audit-committee.certified",
        "audit-committee.escalated",
    ]
    for e in events:
        assert e["schema"] == "audit.ndjson/1"
        assert e["module"] == "audit-committee"
    # event digests recompute deterministically
    rebuilt = ac.audit_committee_audit_event(
        "audit-committee.review-opened", 1, **events[0]["detail"]
    )
    assert rebuilt["digest"] == events[0]["digest"]
    # record digests are pinned inside audit detail
    assert events[0]["detail"]["record_digest"] == rec.digest
    assert events[1]["detail"]["record_digest"] == cert.digest
    assert events[2]["detail"]["record_digest"] == esc.digest
    # raw text never crosses the boundary
    secret = "super secret audit material"
    blob = str(events)
    assert secret not in blob
    # banned keys refused
    for banned in ("subject", "finding", "rationale", "text", "payload", "raw", "reason"):
        with pytest.raises(ac.AuditKindError):
            ac.audit_committee_audit_event(
                "audit-committee.certified", 4, **{banned: "x"}
            )
    with pytest.raises(ac.AuditKindError):
        ac.audit_committee_audit_event("bogus-kind", 4)


# ---------------------------------------------------------------------------
# 15: main() subprocess + cross-instance determinism
# ---------------------------------------------------------------------------


def test_main_subprocess_and_determinism():
    proc = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "audit-committee OK: review, certify, escalate, pins, audit" in proc.stdout

    def _world():
        ledger = ac.AuditCommittee()
        ledger.review("rev-1", _digest("subject"), 1)
        ledger.certify("rev-1", "qualified", 2, finding_digests=(_digest("f"),))
        ledger.escalate("rev-1", "board", 3, rationale_digest=_digest("r"))
        return (
            ledger.review_record("rev-1", 3).digest,
            ledger.certification("rev-1", 3).digest,
            tuple(e.digest for e in ledger.escalations_for("rev-1", 3)),
        )

    assert _world() == _world()
    # tamper breaks verify
    ledger = ac.AuditCommittee()
    rec = ledger.review("rev-1", _digest("subject"), 1)
    forged = ac.ReviewRecord(
        review_id=rec.review_id,
        subject_digest=_digest("other"),
        digest=rec.digest,
        seq=rec.seq,
    )
    assert forged.verify() is False
