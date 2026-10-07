"""Tests for self_critique (self-critique decision ledger, simulated)."""

import ast
import hashlib
import subprocess
import sys
import threading

import pytest

import self_critique as mod
from self_critique import (
    SELF_CRITIQUE_VERSION,
    SCHEMA_PIN,
    CRITIQUE_FINDINGS,
    REVISION_STRATEGIES,
    POSTURES,
    RETIRE_REASONS,
    SelfCritique,
    SelfCritiqueError,
    SeqOrderError,
    BadIdError,
    BadDigestError,
    BadFindingError,
    BadStrategyError,
    UnknownDraftError,
    DuplicateDraftError,
    NoCritiqueError,
    RetiredSystemError,
    BadReasonError,
    AuditKindError,
    DraftRecord,
    CritiqueRecord,
    RevisionRecord,
    CritiqueVerificationReport,
    self_critique_audit_event,
)

MOD = mod.__file__
STDLIB_ALLOW = {
    "__future__", "threading", "dataclasses", "hashlib", "json",
    "typing", "canonical_json", "ast", "pathlib",
}


def _digest(tag: bytes = b"draft") -> str:
    return "sha256:" + hashlib.sha256(tag).hexdigest()


def _sc() -> SelfCritique:
    return SelfCritique()


# 1. version/schema/vocabulary pins
def test_pins():
    assert SELF_CRITIQUE_VERSION == "self-critique.v1"
    assert SCHEMA_PIN == "northstar.self-critique.v1"
    assert CRITIQUE_FINDINGS == (
        "passes", "flawed", "harmful", "refusal-needed",
        "incomplete", "inconclusive")
    assert REVISION_STRATEGIES == (
        "rewrite", "amend", "refuse", "rework-from-critique",
        "escalate", "no-change")
    assert POSTURES == (
        "undrafted", "harmful-detected", "needs-revision", "suspect", "clean")
    assert RETIRE_REASONS == (
        "manual", "superseded", "decommissioned", "completed")


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(open(MOD).read())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= STDLIB_ALLOW, imports - STDLIB_ALLOW
    assert SelfCritique.stdlib_only()


# 3. submit roundtrip + verify() + frozen-ness
def test_submit_roundtrip():
    s = _sc()
    rec = s.submit("draft-1", "sys-1", 1, draft_digest=_digest())
    assert rec.draft_id == "draft-1"
    assert rec.system_id == "sys-1"
    assert rec.verify()
    assert rec.as_dict()["schema"] == SCHEMA_PIN
    assert s.draft_record("draft-1", 2).verify()
    assert s.draft_ids(3) == ("draft-1",)
    with pytest.raises(Exception):
        rec.draft_id = "other"  # frozen
    with pytest.raises(UnknownDraftError):
        s.draft_record("ghost", 4)


# 4. submit bad-input table + seq-burn + rejected rows
def test_submit_bad_inputs():
    s = _sc()
    seq = 0
    bad = [
        (lambda sq: s.submit("", "sys-1", sq), BadIdError),
        (lambda sq: s.submit(123, "sys-1", sq), BadIdError),
        (lambda sq: s.submit("d1", "", sq), BadIdError),
        (lambda sq: s.submit("d1", "sys-1", sq, draft_digest="raw"), BadDigestError),
        (lambda sq: s.submit("d1", "sys-1", sq, draft_digest="md5:abc"), BadDigestError),
        (lambda sq: s.submit("x" * 129, "sys-1", sq), BadIdError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert s.stats(7)["rejected"] == len(bad)  # failed mutations burn seq
    s.submit("d-ok", "sys-1", 8)
    with pytest.raises(SeqOrderError):  # rewind: bare, no row
        s.submit("d-2", "sys-1", 8)
    assert s.stats(9)["rejected"] == len(bad)


# 5. duplicate + retired-id-never-recycled + retire terminality
def test_duplicate_and_retire():
    s = _sc()
    s.submit("d1", "sys-1", 1)
    with pytest.raises(DuplicateDraftError):
        s.submit("d1", "sys-1", 2)
    assert s.stats(3)["rejected"] == 1
    s.retire("sys-1", 4, reason="completed")
    with pytest.raises(RetiredSystemError):
        s.retire("sys-1", 5)
    with pytest.raises(RetiredSystemError):
        s.submit("d2", "sys-1", 6)  # retired system: refused
    with pytest.raises(BadReasonError):
        s.retire("sys-2", 7, reason="vibes")
    assert s.retire_record("sys-1", 8).verify()
    assert s.retired_ids(9) == ("sys-1",)
    assert s.stats(10)["rejected"] == 4


# 6. critique roundtrip + minted ids + verify
def test_critique_roundtrip():
    s = _sc()
    s.submit("d1", "sys-1", 1, draft_digest=_digest())
    c = s.critique("d1", 2, finding="flawed",
                   critique_digest=_digest(b"c"))
    assert c.critique_id == "crt-1"
    assert c.finding == "flawed"
    assert c.verify()
    assert isinstance(c, CritiqueRecord)
    assert s.critique_record("crt-1", 3).verify()
    assert s.critiques_for("d1", 4) == ("crt-1",)
    assert s.critique_ids(5) == ("crt-1",)
    c2 = s.critique("d1", 6, finding="passes")
    assert c2.critique_id == "crt-2"


# 7. critique refusal table + unknown/retired
def test_critique_refusals():
    s = _sc()
    with pytest.raises(UnknownDraftError):
        s.critique("ghost", 1, finding="flawed")
    s.submit("d1", "sys-1", 2)
    s.retire("sys-1", 3)
    with pytest.raises(RetiredSystemError):
        s.critique("d1", 4, finding="flawed")
    s2 = _sc()
    s2.submit("d2", "sys-2", 1)
    seq = 1
    bad = [
        (lambda sq: s2.critique("d2", sq, finding="vibes"), BadFindingError),
        (lambda sq: s2.critique("d2", sq, finding=123), BadFindingError),
        (lambda sq: s2.critique("d2", sq, critique_digest="raw"), BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert s2.stats(5)["rejected"] == len(bad)


# 8. full finding vocabulary acceptance
def test_finding_vocabulary():
    s = _sc()
    s.submit("d1", "sys-1", 1)
    for i, finding in enumerate(CRITIQUE_FINDINGS):
        c = s.critique("d1", i + 2, finding=finding)
        assert c.finding == finding
        assert c.verify()
    rep = s.verify(8, "d1")
    assert rep.n_critiques == len(CRITIQUE_FINDINGS)
    assert rep.finding_tallies == tuple(
        sorted((f, 1) for f in CRITIQUE_FINDINGS))
    assert rep.verify()


# 9. revise roundtrip + minted ids + NoCritiqueError
def test_revise_roundtrip():
    s = _sc()
    s.submit("d1", "sys-1", 1)
    with pytest.raises(NoCritiqueError):  # revise before critique: refused
        s.revise("d1", 2, strategy="rewrite")
    s.critique("d1", 3, finding="flawed")
    r = s.revise("d1", 4, strategy="rework-from-critique",
                 revision_digest=_digest(b"r"))
    assert r.revision_id == "rev-1"
    assert r.strategy == "rework-from-critique"
    assert r.verify()
    assert isinstance(r, RevisionRecord)
    assert s.revision_record("rev-1", 5).verify()
    assert s.revisions_for("d1", 6) == ("rev-1",)
    r2 = s.revise("d1", 7, strategy="amend")  # chainable
    assert r2.revision_id == "rev-2"
    assert s.stats(8)["rejected"] == 1


# 10. revise refusals + strategy vocabulary
def test_revise_refusals_and_vocab():
    s = _sc()
    with pytest.raises(UnknownDraftError):
        s.revise("ghost", 1, strategy="rewrite")
    s.submit("d1", "sys-1", 2)
    s.retire("sys-1", 3)
    with pytest.raises(RetiredSystemError):
        s.revise("d1", 4, strategy="rewrite")
    s2 = _sc()
    s2.submit("d2", "sys-2", 1)
    s2.critique("d2", 2, finding="passes")
    for i, strategy in enumerate(REVISION_STRATEGIES):
        r = s2.revise("d2", i + 3, strategy=strategy)
        assert r.strategy == strategy
        assert r.verify()
    rep = s2.verify(10, "d2")
    assert rep.strategy_tallies == tuple(
        sorted((st, 1) for st in REVISION_STRATEGIES))
    with pytest.raises(BadStrategyError):
        s2.revise("d2", 11, strategy="wing-it")
    assert s2.stats(12)["rejected"] == 1


# 11. verify posture math (all five postures)
def test_verify_posture_math():
    s = _sc()
    assert s.verify(1).posture == "undrafted"
    assert s.verify(1, "").posture == "undrafted"

    s.submit("clean-d", "sys-1", 2)
    s.critique("clean-d", 3, finding="passes")
    assert s.verify(4, "clean-d").posture == "clean"

    s.submit("rev-d", "sys-1", 5)
    s.critique("rev-d", 6, finding="flawed")
    assert s.verify(7, "rev-d").posture == "needs-revision"
    s.critique("rev-d", 8, finding="refusal-needed")
    s.revise("rev-d", 9, strategy="refuse")
    assert s.verify(10, "rev-d").posture == "clean"

    s.submit("harm-d", "sys-1", 11)
    s.critique("harm-d", 12, finding="harmful")
    assert s.verify(13, "harm-d").posture == "harmful-detected"
    assert s.verify(14).posture == "harmful-detected"  # whole-ledger
    s.revise("harm-d", 15, strategy="refuse")
    assert s.verify(16, "harm-d").posture == "clean"

    s.submit("inc-d", "sys-1", 17)
    s.critique("inc-d", 18, finding="inconclusive")
    assert s.verify(19, "inc-d").posture == "suspect"
    s.critique("inc-d", 20, finding="incomplete")
    assert s.verify(21, "inc-d").posture == "needs-revision"

    with pytest.raises(UnknownDraftError):
        s.verify(22, "ghost")


# 12. verify read purity + integrity flip on tamper
def test_verify_read_purity_and_integrity():
    s = _sc()
    s.submit("d1", "sys-1", 1, draft_digest=_digest())
    s.critique("d1", 2, finding="passes")
    n_audit = len(s.audit_log(3))
    rep1 = s.verify(3, "d1")
    rep2 = s.verify(3, "d1")
    assert rep1.verify() and rep2.verify()
    assert rep1.integrity_ok
    assert len(s.audit_log(3)) == n_audit  # reads add no rows
    s2 = _sc()
    s2.submit("d1", "sys-1", 1, draft_digest=_digest())
    c = s2.critique("d1", 2, finding="passes")
    import dataclasses
    tampered = dataclasses.replace(c, finding="harmful")
    assert tampered.verify() is False
    object.__setattr__(c, "finding", "harmful")
    assert c.verify() is False
    rep = s2.verify(3, "d1")
    assert rep.verify() is True
    assert rep.integrity_ok is False


# 13. seq discipline (rewind bare, malformed seqs, failed-mutation-consumes-seq)
def test_seq_discipline():
    s = _sc()
    s.submit("d1", "sys-1", 5)
    with pytest.raises(SeqOrderError):
        s.submit("d2", "sys-1", 5)  # rewind: bare
    assert s.stats(6)["rejected"] == 0  # no row booked for bare rewind
    for bad in (True, 0, -1, 1.5, "2", None):
        with pytest.raises(SeqOrderError):
            s.submit("d2", "sys-1", bad)
    s.submit("d2", "sys-1", 7)
    assert s.draft_ids(8) == ("d1", "d2")
    # read views validate seq shape only
    for bad in (True, 0, -1, 1.5, "2", None):
        with pytest.raises(SeqOrderError):
            s.draft_record("d1", bad)
    # failed mutation consumes seq + books rejected row
    with pytest.raises(BadIdError):
        s.submit("", "sys-1", 9)
    assert s.stats(10)["rejected"] == 1


# 14. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    s = _sc()
    s.submit("d1", "sys-1", 1, draft_digest=_digest())
    s.critique("d1", 2, finding="flawed",
               critique_digest=_digest(b"c"))
    s.revise("d1", 3, strategy="rewrite",
             revision_digest=_digest(b"r"))
    rows = s.audit_log(4)
    assert [r["kind"] for r in rows] == [
        "self-critique.submitted",
        "self-critique.critiqued",
        "self-critique.revised",
    ]
    for row in rows:
        for key in row["details"]:
            assert key not in mod._BANNED_AUDIT_KEYS
    with pytest.raises(AuditKindError):
        self_critique_audit_event("submitted", {"draft_id": "x", "text": "raw"})
    with pytest.raises(AuditKindError):
        self_critique_audit_event("bogus-kind", 1)
    with pytest.raises(AuditKindError):
        self_critique_audit_event("submitted", "not-a-dict")


# 15. cross-instance digest determinism + 8-thread read smoke + main()
def test_determinism_and_concurrency_and_main():
    def build():
        s = _sc()
        s.submit("d1", "sys-1", 1, draft_digest=_digest())
        s.critique("d1", 2, finding="flawed")
        s.revise("d1", 3, strategy="rewrite")
        return s

    s1, s2 = build(), build()
    assert s1.draft_record("d1", 4).digest == s2.draft_record("d1", 4).digest
    assert s1.critique_record("crt-1", 4).digest == \
        s2.critique_record("crt-1", 4).digest
    assert s1.revision_record("rev-1", 4).digest == \
        s2.revision_record("rev-1", 4).digest
    rec = s1.critique_record("crt-1", 4)
    with pytest.raises(Exception):
        rec.finding = "passes"  # frozen

    s3 = _sc()
    s3.submit("d1", "sys-1", 1)
    s3.critique("d1", 2, finding="passes")
    results = []

    def worker():
        results.append(s3.verify(3, "d1").posture)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results == ["clean"] * 8

    proc = subprocess.run(
        [sys.executable, MOD],
        capture_output=True, text=True, cwd="/tmp", timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "self-critique OK: submit, critique, revise, verify, pins, audit")
