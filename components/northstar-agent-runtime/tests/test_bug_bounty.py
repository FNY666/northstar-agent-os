"""Tests for bug_bounty.py: submit/triage/reward decision ledger (simulated)."""

import ast
import importlib.util
import subprocess
import sys
import threading
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
MODULE_PATH = HERE.parent / "bug_bounty.py"


def _load():
    spec = importlib.util.spec_from_file_location("bug_bounty", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["bug_bounty"] = module  # frozen dataclasses need a registered module
    spec.loader.exec_module(module)
    return module


bb = _load()

DIGEST = "sha256:" + "ab" * 32
DIGEST2 = "sha256:" + "cd" * 32
BAD_DIGESTS = ["", "sha256:xyz", "ab" * 32, "sha256:" + "zz" * 32, "SHA256:" + "ab" * 32, None, 123]


def _fresh():
    return bb.BugBounty()


# 1 -- pins ---------------------------------------------------------------


def test_version_and_schema_pins():
    assert bb.BUG_BOUNTY_VERSION == "bug-bounty.v1"
    assert bb.BUG_BOUNTY_SCHEMA == "northstar.bug-bounty.v1"
    assert bb.AUDIT_SCHEMA == "audit.ndjson/1"
    assert set(bb.SEVERITIES) == {"critical", "high", "medium", "low", "informational"}
    assert set(bb.VERDICTS) == {"accepted", "duplicate", "invalid", "needs-more-info", "out-of-scope"}


# 2 -- stdlib only --------------------------------------------------------


def test_stdlib_only():
    tree = ast.parse(MODULE_PATH.read_text())
    allowed = {
        "__future__",
        "hashlib",
        "threading",
        "dataclasses",
        "typing",
        "json",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert node.module.split(".")[0] in allowed, node.module


# 3 -- submit roundtrip ----------------------------------------------------


def test_submit_roundtrip_and_frozen():
    inst = _fresh()
    rec = inst.submit("rpt-1", 1, severity="high", title_digest=DIGEST, report_digest=DIGEST2)
    assert rec.report_id == "rpt-1"
    assert rec.severity == "high"
    assert rec.title_digest == DIGEST
    assert rec.report_digest == DIGEST2
    assert rec.seq == 1
    assert rec.verify()
    with pytest.raises(Exception):
        rec.severity = "low"  # frozen
    got = inst.report_record("rpt-1", 2)
    assert got == rec
    assert "rpt-1" in inst.report_ids(3)
    assert "rpt-1" in inst.pending_ids(4)


# 4 -- submit bad inputs ---------------------------------------------------


def test_submit_bad_inputs_burn_seq_and_book_rejected():
    inst = _fresh()
    before = len(inst.audit_log(1))
    seq = 2
    cases = [
        lambda s: inst.submit("", s),  # empty id
        lambda s: inst.submit("a b", s),  # whitespace id
        lambda s: inst.submit(None, s),  # non-str id
        lambda s: inst.submit("ok-1", s, severity="urgent"),  # bad severity
        lambda s: inst.submit("ok-1", s, severity=None),  # bad severity
        lambda s: inst.submit("ok-1", s, title_digest="sha256:xyz"),  # bad digest
        lambda s: inst.submit("ok-1", s, report_digest="zz" * 32),  # bad digest
    ]
    for fn in cases:
        with pytest.raises(bb.BugBountyError):
            fn(seq)
        seq += 1
    # all failures consumed their seq and booked a rejected row
    log = inst.audit_log(seq)
    rejected = [e for e in log if e["kind"] == "bug-bounty.rejected"]
    assert len(rejected) == len(cases)
    assert len(log) == before + len(cases)
    # duplicate refusal also burns
    inst.submit("dup-1", seq)
    with pytest.raises(bb.DuplicateReportError):
        inst.submit("dup-1", seq + 1)
    log2 = inst.audit_log(seq + 2)
    assert sum(1 for e in log2 if e["kind"] == "bug-bounty.rejected") == len(cases) + 1


# 5 -- triage lifecycle ----------------------------------------------------


def test_triage_roundtrip_all_verdicts():
    inst = _fresh()
    seq = 1
    for i, verdict in enumerate(bb.VERDICTS):
        rid = f"rpt-t{i}"
        inst.submit(rid, seq)
        seq += 1
        tri = inst.triage(rid, seq, verdict, analyst="alice")
        seq += 1
        assert tri.triage_id == f"trg-{i + 1}"
        assert tri.verdict == verdict
        assert tri.verify()
        assert inst.triage_record(rid, seq - 1) == tri
    assert inst.pending_ids(seq) == ()


def test_triage_refusals():
    inst = _fresh()
    inst.submit("rpt-a", 1)
    inst.submit("rpt-b", 2)
    with pytest.raises(bb.UnknownReportError):
        inst.triage("nope", 3, "accepted")
    with pytest.raises(bb.BadVerdictError):
        inst.triage("rpt-a", 4, "maybe")
    with pytest.raises(bb.BadAnalystError):
        inst.triage("rpt-a", 5, "accepted", analyst="a b")
    inst.triage("rpt-b", 6, "invalid")
    with pytest.raises(bb.AlreadyTriagedError):
        inst.triage("rpt-b", 7, "accepted")
    log = inst.audit_log(8)
    assert sum(1 for e in log if e["kind"] == "bug-bounty.rejected") == 4


# 6 -- reward lifecycle ----------------------------------------------------


def test_reward_roundtrip_and_gating():
    inst = _fresh()
    inst.submit("rpt-1", 1, severity="critical")
    inst.triage("rpt-1", 2, "accepted")
    rwd = inst.reward("rpt-1", 3, 250000, currency="USD")
    assert rwd.reward_id == "rwd-1"
    assert rwd.amount_cents == 250000
    assert rwd.currency == "USD"
    assert rwd.verify()
    assert inst.reward_record("rpt-1", 4) == rwd
    # zero-amount reward is allowed (recognition-only)
    inst.submit("rpt-2", 5)
    inst.triage("rpt-2", 6, "accepted")
    zero = inst.reward("rpt-2", 7, 0, currency="EUR")
    assert zero.amount_cents == 0 and zero.verify()


def test_reward_refusals():
    inst = _fresh()
    inst.submit("rpt-1", 1)
    inst.submit("rpt-2", 2)
    inst.triage("rpt-2", 3, "duplicate")
    with pytest.raises(bb.UnknownReportError):
        inst.reward("nope", 4, 100)
    with pytest.raises(bb.NotTriagedError):
        inst.reward("rpt-1", 5, 100)
    with pytest.raises(bb.NotAcceptedError):
        inst.reward("rpt-2", 6, 100)
    inst.triage("rpt-1", 7, "accepted")
    with pytest.raises(bb.BadAmountError):
        inst.reward("rpt-1", 8, True)  # bool refused
    with pytest.raises(bb.BadAmountError):
        inst.reward("rpt-1", 9, -1)
    with pytest.raises(bb.BadAmountError):
        inst.reward("rpt-1", 10, 99.5)  # float refused
    with pytest.raises(bb.BadCurrencyError):
        inst.reward("rpt-1", 11, 100, currency="usd")
    with pytest.raises(bb.BadCurrencyError):
        inst.reward("rpt-1", 12, 100, currency="US")
    ok = inst.reward("rpt-1", 13, 100)
    assert ok.verify()
    with pytest.raises(bb.AlreadyRewardedError):
        inst.reward("rpt-1", 14, 200)
    log = inst.audit_log(15)
    assert sum(1 for e in log if e["kind"] == "bug-bounty.rejected") == 9


# 7 -- seq discipline ------------------------------------------------------


def test_seq_discipline():
    inst = _fresh()
    inst.submit("rpt-1", 5)
    # rewind raises bare: no seq consumption, no rejected row
    before = len(inst.audit_log(6))
    with pytest.raises(bb.SeqOrderError):
        inst.submit("rpt-2", 5)
    with pytest.raises(bb.SeqOrderError):
        inst.submit("rpt-2", 1)
    assert len(inst.audit_log(6)) == before
    # malformed seqs raise bare
    for bad in (0, -3, True, "7", 7.0, None):
        with pytest.raises(bb.SeqOrderError):
            inst.submit("rpt-2", bad)
    assert len(inst.audit_log(6)) == before
    # reads validate seq shape too
    with pytest.raises(bb.SeqOrderError):
        inst.report_ids(0)


# 8 -- read purity and status ----------------------------------------------


def test_views_are_pure_reads():
    inst = _fresh()
    inst.submit("rpt-1", 1, severity="medium", title_digest=DIGEST)
    inst.triage("rpt-1", 2, "accepted")
    inst.reward("rpt-1", 3, 1000)
    n_before = len(inst.audit_log(4))
    rep = inst.status("rpt-1", 4)
    assert rep.verify() and rep.integrity_ok
    assert rep.submitted and rep.triaged and rep.rewarded
    assert rep.severity == "medium" and rep.verdict == "accepted"
    assert rep.amount_cents == 1000 and rep.currency == "USD"
    assert inst.status("rpt-1", 4) == rep  # same seq twice is fine
    assert len(inst.audit_log(4)) == n_before  # no audit rows from reads
    stats = inst.stats(4)
    assert stats["reports"] == 1 and stats["triaged"] == 1
    assert stats["rewarded"] == 1 and stats["pending"] == 0
    assert stats["verdicts"]["accepted"] == 1
    assert stats["total_reward_cents"] == 1000
    with pytest.raises(bb.UnknownReportError):
        inst.status("nope", 4)
    # unrewarded report: status shows empty reward fields
    inst.submit("rpt-2", 5)
    rep2 = inst.status("rpt-2", 6)
    assert not rep2.triaged and not rep2.rewarded and rep2.amount_cents == 0


# 9 -- audit shapes and leak ban --------------------------------------------


def test_audit_shapes_and_leak_ban():
    inst = _fresh()
    inst.submit("rpt-1", 1, title_digest=DIGEST)
    inst.triage("rpt-1", 2, "accepted", analyst="alice")
    inst.reward("rpt-1", 3, 500)
    log = inst.audit_log(4)
    kinds = [e["kind"] for e in log]
    assert kinds == ["bug-bounty.submitted", "bug-bounty.triaged", "bug-bounty.rewarded"]
    for e in log:
        assert e["schema"] == "audit.ndjson/1"
        assert e["module"] == "northstar.bug-bounty.v1"
    # raw content keys banned at the audit boundary
    for banned in ("title", "description", "report", "poc", "exploit", "steps", "code"):
        with pytest.raises(bb.AuditKindError):
            bb.bug_bounty_audit_event("bug-bounty.submitted", 9, **{banned: "x"})
    with pytest.raises(bb.AuditKindError):
        bb.bug_bounty_audit_event("nope.kind", 9)


# 10 -- cross-instance determinism and tamper --------------------------------


def test_cross_instance_determinism_and_tamper():
    a, b = _fresh(), _fresh()
    ra = a.submit("rpt-1", 1, severity="low", title_digest=DIGEST)
    rb = b.submit("rpt-1", 1, severity="low", title_digest=DIGEST)
    assert ra.digest == rb.digest
    ta = a.triage("rpt-1", 2, "accepted")
    tb = b.triage("rpt-1", 2, "accepted")
    assert ta.digest == tb.digest
    # tamper breaks verify
    object.__setattr__(ra, "severity", "critical")
    assert not ra.verify()
    assert a.status("rpt-1", 3).integrity_ok is False


# 11 -- concurrency smoke ----------------------------------------------------


def test_concurrent_reads():
    inst = _fresh()
    inst.submit("rpt-1", 1)
    inst.triage("rpt-1", 2, "accepted")
    errors = []

    def reader():
        try:
            for _ in range(50):
                inst.status("rpt-1", 3)
                inst.report_ids(3)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


# 12 -- main self-check -------------------------------------------------------


def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MODULE_PATH)], capture_output=True, text=True, timeout=30
    )
    assert proc.returncode == 0, proc.stderr
    assert "bug-bounty OK" in proc.stdout


# 13 -- standalone import -----------------------------------------------------


def test_standalone_import_from_tmp(tmp_path):
    code = (
        "import importlib.util, sys\n"
        f"p = {str(MODULE_PATH)!r}\n"
        "spec = importlib.util.spec_from_file_location('bb_standalone', p)\n"
        "m = importlib.util.module_from_spec(spec)\n"
        "sys.modules['bb_standalone'] = m\n"
        "spec.loader.exec_module(m)\n"
        "b = m.BugBounty()\n"
        "b.submit('r', 1)\n"
        "b.triage('r', 2, 'accepted')\n"
        "b.reward('r', 3, 42)\n"
        "print('standalone ok')\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=30, cwd=str(tmp_path)
    )
    assert proc.returncode == 0, proc.stderr
    assert "standalone ok" in proc.stdout


# 14 -- currency edge cases ----------------------------------------------------


def test_currency_and_amount_edges():
    inst = _fresh()
    inst.submit("rpt-1", 1)
    inst.triage("rpt-1", 2, "accepted")
    seq = 3
    for cur in ("USD", "EUR", "GBP", "JPY", "CNY"):
        rid = f"rpt-{cur}"
        inst.submit(rid, seq)
        seq += 1
        inst.triage(rid, seq, "accepted")
        seq += 1
        rwd = inst.reward(rid, seq, 10**12, currency=cur)
        seq += 1
        assert rwd.verify() and rwd.currency == cur
    inst.submit("rpt-x", seq)
    seq += 1
    inst.triage("rpt-x", seq, "accepted")
    seq += 1
    with pytest.raises(bb.BadCurrencyError):
        inst.reward("rpt-x", seq, 1, currency="US1")


# 15 -- py_compile -------------------------------------------------------------


def test_py_compile():
    proc = subprocess.run(
        [sys.executable, "-m", "py_compile", str(MODULE_PATH)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
