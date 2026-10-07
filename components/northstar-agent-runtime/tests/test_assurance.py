"""Tests for the assurance-case (argue/verify/maintain) ledger."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import assurance
from assurance import (
    Assurance, AssuranceError, AuditKindError, BadEvidenceError,
    BadEvidenceKindError, BadGoalError, BadReasonError, BadStrategyError,
    BadStrategyKindError, CycleError, DuplicateEvidenceError,
    DuplicateGoalError, DuplicateStrategyError, SeqOrderError,
    UnknownGoalError, assurance_audit_event, ASSURANCE_SCHEMA,
    ASSURANCE_VERSION, EVIDENCE_KINDS, REASONS, STRATEGY_KINDS,
)

_HERE = Path(__file__).resolve().parent.parent

D1 = "sha256:" + "1" * 64
D2 = "sha256:" + "2" * 64
D3 = "sha256:" + "3" * 64
D4 = "sha256:" + "4" * 64
D5 = "sha256:" + "5" * 64


def _led():
    return Assurance()


# 1 -- version/schema pins + stdlib-only AST check ----------------------------

def test_version_schema_pins_and_stdlib_only():
    assert assurance.ASSURANCE_VERSION == "assurance.v1"
    assert assurance.ASSURANCE_SCHEMA == "northstar.assurance.v1"
    assert assurance.AUDIT_SCHEMA == "audit.ndjson/1"
    assert len(STRATEGY_KINDS) == 6 and len(EVIDENCE_KINDS) == 9
    assert len(REASONS) == 5
    tree = ast.parse((_HERE / "assurance.py").read_text())
    allowed = {"__future__", "hashlib", "threading", "dataclasses",
               "typing", "canonical_json", "json"}  # json = fallback
    # canonicalizer fallback only (sibling convention)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert node.module.split(".")[0] in allowed, node.module


# 2 -- goal roundtrip + record verify ------------------------------------------

def test_goal_roundtrip_and_verify():
    a = _led()
    rec = a.goal("g-top", D1, 1)
    assert rec.goal_id == "g-top" and rec.claim_digest == D1 and rec.seq == 1
    assert rec.digest.startswith("sha256:")
    assert rec.verify(D1)
    assert not rec.verify(D2)
    # frozen
    with pytest.raises(Exception):
        rec.goal_id = "x"  # type: ignore[misc]


# 3 -- duplicate / bad goal ids + seq-burn + rejected rows ---------------------

def test_goal_bad_inputs_and_seq_burn():
    a = _led()
    a.goal("g-1", D1, 1)
    rejected_before = a.stats(2)["audit_rows"]
    cases = [
        ("g-1", D1, 2, DuplicateGoalError),
        ("", D1, 3, BadGoalError),
        ("   ", D1, 4, BadGoalError),
        ("g x", D1, 5, BadGoalError),
        ("x" * 257, D1, 6, BadGoalError),
        (123, D1, 7, BadGoalError),
        (True, D1, 8, BadGoalError),
        ("g-2", "raw-claim-text", 9, BadGoalError),
        ("g-2", "md5:abc", 10, BadGoalError),
        ("g-2", 42, 11, BadGoalError),
    ]
    for gid, digest, seq, exc in cases:
        with pytest.raises(exc):
            a.goal(gid, digest, seq)
    st = a.stats(12)
    assert st["last_seq"] == 11
    rows = a.audit_log(13)
    assert len(rows) == rejected_before + 10
    assert all(r["kind"] == "rejected" for r in rows[rejected_before:])
    assert a.goal("g-2", D2, 12).seq == 12  # ledger still usable


# 4 -- argue roundtrip ----------------------------------------------------------

def test_argue_roundtrip():
    a = _led()
    a.goal("g-top", D1, 1)
    a.goal("g-a", D2, 2)
    a.goal("g-b", D3, 3)
    rec = a.argue("s-1", "g-top", ("g-a", "g-b"), "decomposition", 4)
    assert rec.strategy_id == "s-1"
    assert rec.conclusion_id == "g-top"
    assert rec.premise_ids == ("g-a", "g-b")
    assert rec.strategy_kind == "decomposition"
    assert rec.verify("g-top", ("g-a", "g-b"), "decomposition")
    assert not rec.verify("g-top", ("g-a",), "decomposition")


# 5 -- argue fail-closed table ---------------------------------------------------

def test_argue_bad_inputs():
    a = _led()
    a.goal("g-top", D1, 1)
    a.goal("g-a", D2, 2)
    a.argue("s-1", "g-top", ("g-a",), "decomposition", 3)
    cases = [
        (("s-1", "g-top", ("g-a",), "decomposition"), DuplicateStrategyError),
        (("s-2", "g-top", (), "decomposition"), BadStrategyError),
        (("s-2", "g-top", ("g-a", "g-a"), "decomposition"), BadStrategyError),
        (("s-2", "g-top", ("g-a", "g-nope"), "decomposition"),
         UnknownGoalError),
        (("s-2", "g-nope", ("g-a",), "decomposition"), UnknownGoalError),
        (("s-2", "g-top", "g-a", "decomposition"), BadStrategyError),
        (("s-2", "g-top", ("g-a",), "sorcery"), BadStrategyKindError),
        (("s-2", "g-top", ("g-a",), None), BadStrategyKindError),
        (("", "g-top", ("g-a",), "decomposition"), BadStrategyError),
    ]
    seq = 4
    for args, exc in cases:
        with pytest.raises(exc):
            a.argue(*args, seq)
        seq += 1
    assert a.stats(seq)["last_seq"] == seq - 1


def test_argue_self_reference_and_cycle():
    a = _led()
    a.goal("g-1", D1, 1)
    with pytest.raises(CycleError):
        a.argue("s-x", "g-1", ("g-1",), "decomposition", 2)
    a.goal("g-2", D2, 3)
    a.argue("s-1", "g-1", ("g-2",), "decomposition", 4)
    # g-1 -> g-2 already booked; booking g-2 => g-1 would close a cycle
    with pytest.raises(CycleError):
        a.argue("s-2", "g-2", ("g-1",), "decomposition", 5)
    # longer cycle: g-2 => g-3 => g-1 would also close via g-1 -> g-2
    a.goal("g-3", D3, 6)
    a.argue("s-3", "g-3", ("g-1",), "decomposition", 7)
    with pytest.raises(CycleError):
        a.argue("s-4", "g-2", ("g-3",), "decomposition", 8)


# 6 -- evidence roundtrip + bad inputs --------------------------------------------

def test_evidence_roundtrip_and_bad_inputs():
    a = _led()
    a.goal("g-top", D1, 1)
    rec = a.evidence("e-1", "g-top", "test-result", D2, 2)
    assert rec.evidence_id == "e-1" and rec.evidence_id in a.evidence_ids(3)
    assert rec.verify("g-top", "test-result", D2)
    assert not rec.verify("g-top", "inspection", D2)
    with pytest.raises(DuplicateEvidenceError):
        a.evidence("e-1", "g-top", "test-result", D2, 3)
    with pytest.raises(UnknownGoalError):
        a.evidence("e-2", "g-nope", "test-result", D2, 4)
    with pytest.raises(BadEvidenceKindError):
        a.evidence("e-2", "g-top", "vibes", D2, 5)
    with pytest.raises(BadEvidenceError):
        a.evidence("e-2", "g-top", "test-result", "not-a-digest", 6)
    with pytest.raises(BadEvidenceError):
        a.evidence("", "g-top", "test-result", D2, 7)
    # every evidence kind accepted
    for i, kind in enumerate(EVIDENCE_KINDS):
        a.evidence(f"e-kind-{i}", "g-top", kind, D3, 8 + i)


# 7 -- verify(): supported graph ----------------------------------------------------

def test_verify_supported_graph():
    a = _led()
    a.goal("g-top", D1, 1)
    a.goal("g-a", D2, 2)
    a.goal("g-b", D3, 3)
    a.argue("s-1", "g-top", ("g-a", "g-b"), "decomposition", 4)
    a.evidence("e-a", "g-a", "test-result", D4, 5)
    a.evidence("e-b", "g-b", "inspection", D5, 6)
    rep = a.verify("g-top", 7)
    assert rep.ok is True
    assert rep.supported is True
    assert rep.gaps == ()
    assert rep.goals_checked == 3
    assert rep.digest.startswith("sha256:")


# 8 -- verify(): gaps are data -------------------------------------------------------

def test_verify_gaps_as_data():
    a = _led()
    a.goal("g-top", D1, 1)
    a.goal("g-a", D2, 2)
    a.goal("g-b", D3, 3)
    a.argue("s-1", "g-top", ("g-a", "g-b"), "decomposition", 4)
    a.evidence("e-a", "g-a", "test-result", D4, 5)
    rep = a.verify("g-top", 6)
    assert rep.ok is True
    assert rep.supported is False
    assert rep.gaps == ("g-b", "g-top")
    # a bare top goal with no argument at all
    b = _led()
    b.goal("g-lonely", D1, 1)
    rep2 = b.verify("g-lonely", 2)
    assert rep2.supported is False and rep2.gaps == ("g-lonely",)


def test_verify_tamper_detected_as_data():
    a = _led()
    a.goal("g-top", D1, 1)
    a.evidence("e-1", "g-top", "test-result", D2, 2)
    assert a.verify("g-top", 3).ok is True
    rec = a.goal_record("g-top", 4)
    object.__setattr__(rec, "digest", "sha256:" + "f" * 64)
    rep = a.verify("g-top", 5)
    assert rep.ok is False


# 9 -- maintain roundtrip + bad inputs -------------------------------------------------

def test_maintain_roundtrip_and_bad_inputs():
    a = _led()
    a.goal("g-top", D1, 1)
    m1 = a.maintain("g-top", 2)
    assert m1.maintain_id == "mnt-1" and m1.reason == "scheduled-review"
    assert m1.verify("g-top", "scheduled-review")
    m2 = a.maintain("g-top", 3, reason="post-change")
    assert m2.maintain_id == "mnt-2"
    for i, reason in enumerate(REASONS):
        a.maintain("g-top", 4 + i, reason=reason)
    with pytest.raises(UnknownGoalError):
        a.maintain("g-nope", 10)
    with pytest.raises(BadReasonError):
        a.maintain("g-top", 11, reason="whenever")
    with pytest.raises(BadGoalError):
        a.maintain("", 12)
    assert a.maintain_ids(13) == (
        "mnt-1", "mnt-2", "mnt-3", "mnt-4", "mnt-5", "mnt-6", "mnt-7")


# 10 -- seq discipline --------------------------------------------------------------------

def test_seq_discipline():
    a = _led()
    # rewind raises bare: no consumption, no rejected row
    a.goal("g-1", D1, 1)
    rows_before = len(a.audit_log(2))
    with pytest.raises(SeqOrderError):
        a.goal("g-2", D2, 1)
    assert a.stats(3)["last_seq"] == 1
    assert len(a.audit_log(4)) == rows_before
    # malformed seqs raise before any booking
    for bad in (True, "1", 1.5, None, -3):
        with pytest.raises(SeqOrderError):
            a.goal("g-bad", D3, bad)
        with pytest.raises(SeqOrderError):
            a.verify("g-1", bad)
    assert a.stats(5)["last_seq"] == 1
    # failed mutation consumes seq + books rejected
    with pytest.raises(DuplicateGoalError):
        a.goal("g-1", D2, 6)
    assert a.stats(7)["last_seq"] == 6
    assert a.audit_log(8)[-1]["kind"] == "rejected"


# 11 -- view read purity --------------------------------------------------------------------

def test_verify_read_purity():
    a = _led()
    a.goal("g-top", D1, 1)
    a.evidence("e-1", "g-top", "test-result", D2, 2)
    rows_before = len(a.audit_log(3))
    r1 = a.verify("g-top", 2)
    r2 = a.verify("g-top", 2)
    assert r1.digest == r2.digest  # same seq twice is legal
    assert len(a.audit_log(4)) == rows_before  # no audit rows written
    assert a.stats(5)["last_seq"] == 2  # seq not consumed
    # a later mutation at a higher seq still succeeds
    assert a.maintain("g-top", 6).maintain_id == "mnt-1"
    with pytest.raises(UnknownGoalError):
        a.verify("g-nope", 7)


# 12 -- audit shapes + leak ban + bad kind -------------------------------------------------------

def test_audit_shapes_leak_ban_and_bad_kind():
    a = _led()
    a.goal("g-top", D1, 1)
    rows = a.audit_log(2)
    assert rows[0]["kind"] == "goal-declared"
    assert rows[0]["schema"] == "audit.ndjson/1"
    assert rows[0]["module"] == "assurance.v1"
    # banned keys raise; exact-key matching (no substring false positives)
    for banned in ("claim", "text", "payload", "raw", "value", "data",
                   "variables", "evidence"):
        with pytest.raises(AuditKindError):
            assurance_audit_event("goal-declared", {banned: "x"}, 3)
    ok = assurance_audit_event(
        "goal-declared", {"goal_id": "g-top", "claim_digest": D1}, 4)
    assert ok["kind"] == "goal-declared"
    with pytest.raises(AuditKindError):
        assurance_audit_event("nope", {}, 5)


# 13 -- cross-instance digest determinism ----------------------------------------------------------

def test_cross_instance_determinism():
    def build():
        x = Assurance()
        x.goal("g-top", D1, 1)
        x.goal("g-a", D2, 2)
        x.argue("s-1", "g-top", ("g-a",), "empirical", 3)
        x.evidence("e-1", "g-a", "simulation", D3, 4)
        x.maintain("g-top", 5)
        return x

    x, y = build(), build()
    assert x.goal_record("g-top", 6).digest == y.goal_record("g-top", 6).digest
    assert x.verify("g-top", 7).digest == y.verify("g-top", 7).digest
    assert x.verify("g-top", 8).supported is True


# 14 -- views/stats --------------------------------------------------------------------------

def test_views_and_stats():
    a = _led()
    assert a.goal_ids(1) == ()
    a.goal("g-b", D1, 1)
    a.goal("g-a", D2, 2)
    assert a.goal_ids(3) == ("g-a", "g-b")
    assert a.goal_record("g-a", 4).claim_digest == D2
    st = a.stats(5)
    assert st["goals"] == 2 and st["strategies"] == 0
    assert st["evidence"] == 0 and st["maintains"] == 0
    assert st["last_seq"] == 2


# 15 -- main() subprocess ----------------------------------------------------------------------------

def test_main_subprocess():
    r = subprocess.run([sys.executable, str(_HERE / "assurance.py")],
                       capture_output=True, text=True, cwd=str(_HERE))
    assert r.returncode == 0, r.stderr
    assert "assurance OK" in r.stdout


# standalone import check (mirrors sibling convention) ----------------------------------------------

def test_standalone_importable():
    import shutil
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        shutil.copy(_HERE / "assurance.py", Path(td) / "assurance.py")
        r = subprocess.run(
            [sys.executable, "-c",
             "import assurance; a = assurance.Assurance(); "
             "a.goal('g', 'sha256:" + "0" * 64 + "', 1); print('ok')"],
            capture_output=True, text=True, cwd=td)
        assert r.returncode == 0, r.stderr
        assert "ok" in r.stdout
