"""Tests for the ai_oversight decision ledger (Simulated).

House contract: frozen records, caller int seqs strictly increasing
with claim-then-burn, no wall-clock, RLock-guarded, fail-closed
taxonomy, stdlib-only AST-verified, sha256: digest pins, audit.ndjson/1.
"""
from __future__ import annotations

import ast
import hashlib
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import ai_oversight
from ai_oversight import (
    AI_OVERSIGHT_VERSION,
    AI_OVERSIGHT_SCHEMA,
    AIOversight,
    AIOversightError,
    AuditKindError,
    BadDigestError,
    BadOutcomeError,
    BadOversightKindError,
    BadReasonError,
    BadSystemError,
    KIND_AUTOMATED_SCREENING,
    KIND_DEEP_REVIEW,
    KIND_ESCALATED_REVIEW,
    KIND_CONTINUOUS_MONITORING,
    KIND_HUMAN_IN_THE_LOOP,
    KIND_HUMAN_ON_THE_LOOP,
    KIND_HUMAN_IN_COMMAND,
    KIND_SPOT_CHECK,
    OUTCOMES,
    OUTCOME_ADEQUATE,
    OUTCOME_INADEQUATE,
    OUTCOME_INCONCLUSIVE,
    OUTCOME_NOT_ASSESSED,
    OVERSIGHT_KINDS,
    POSTURES,
    POSTURE_ADEQUATE,
    POSTURE_CONTESTED,
    POSTURE_NOT_ASSESSED,
    POSTURE_OVERSIGHT_LAPSED,
    POSTURE_UNWATCHED,
    RetiredSystemError,
    SeqOrderError,
    UnknownOversightError,
    UnknownSystemError,
    ai_oversight_audit_event,
    stdlib_only,
)


def _good_digest() -> str:
    return "sha256:" + "ab" * 32


# ---------------------------------------------------------------------------
# 1. pins
# ---------------------------------------------------------------------------

def test_version_and_schema_pins() -> None:
    assert AI_OVERSIGHT_VERSION == "ai-oversight.v1"
    assert AI_OVERSIGHT_SCHEMA == "northstar.ai-oversight.v1"
    assert len(OVERSIGHT_KINDS) == 8
    assert len(OUTCOMES) == 4
    assert len(POSTURES) == 5


# ---------------------------------------------------------------------------
# 2. stdlib-only AST check
# ---------------------------------------------------------------------------

def test_stdlib_only() -> None:
    assert stdlib_only()
    src = Path(ai_oversight.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    allowed = set(getattr(sys, "stdlib_module_names", ())) | {"canonical_json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            assert node.module is None or node.module.split(".")[0] in allowed


# ---------------------------------------------------------------------------
# 3. oversee roundtrip + verify + frozen-ness
# ---------------------------------------------------------------------------

def test_oversee_roundtrip_verify_frozen() -> None:
    o = AIOversight()
    rec = o.oversee("sys-1", 1, oversight_kind=KIND_HUMAN_IN_COMMAND,
                    outcome=OUTCOME_ADEQUATE,
                    oversight_digest=_good_digest())
    assert rec.oversight_id == "ovr-1"
    assert rec.system_id == "sys-1"
    assert rec.schema == AI_OVERSIGHT_SCHEMA
    assert rec.version == AI_OVERSIGHT_VERSION
    assert rec.verify()
    with pytest.raises(Exception):
        rec.outcome = OUTCOME_INADEQUATE  # frozen dataclass


# ---------------------------------------------------------------------------
# 4. bad-input table + seq-burn + rejected-row accounting + rewind bare
# ---------------------------------------------------------------------------

def test_oversee_bad_inputs_burn_seq() -> None:
    o = AIOversight()
    bad_calls = [
        lambda: o.oversee("", 1),
        lambda: o.oversee("sys x", 2),
        lambda: o.oversee("sys-1", 3, oversight_kind="not-a-kind"),
        lambda: o.oversee("sys-1", 4, outcome="not-an-outcome"),
        lambda: o.oversee("sys-1", 5, oversight_digest="sha256:zzz"),
        lambda: o.oversee("sys-1", 6, oversight_digest=123),
    ]
    errors = (BadSystemError, BadOversightKindError, BadOutcomeError,
              BadDigestError)
    for fn in bad_calls:
        with pytest.raises(errors):
            fn()
    # every failed mutation consumed its seq and booked a rejected row
    rows = [e for e in o.audit_log(100) if e["kind"] == "rejected"]
    assert len(rows) == 6
    assert o.stats(100)["seq"] == 6
    # seq rewind raises bare: no burn, no audit row
    with pytest.raises(SeqOrderError):
        o.oversee("sys-1", 1)
    assert len([e for e in o.audit_log(100)
                if e["kind"] == "rejected"]) == 6


# ---------------------------------------------------------------------------
# 5. full 8-kind vocabulary acceptance
# ---------------------------------------------------------------------------

def test_all_oversight_kinds_accepted() -> None:
    o = AIOversight()
    for i, kind in enumerate(OVERSIGHT_KINDS):
        rec = o.oversee(f"sys-{i}", i + 1, oversight_kind=kind)
        assert rec.oversight_kind == kind and rec.verify()
    assert o.stats(100)["sessions"] == 8


# ---------------------------------------------------------------------------
# 6. full 4-outcome vocabulary acceptance
# ---------------------------------------------------------------------------

def test_all_outcomes_accepted() -> None:
    o = AIOversight()
    for i, outcome in enumerate(OUTCOMES):
        rec = o.oversee("sys-1", i + 1, outcome=outcome)
        assert rec.outcome == outcome and rec.verify()
    assert o.stats(100)["sessions"] == 4


# ---------------------------------------------------------------------------
# 7. evaluate posture math (all reachable postures + precedence)
# ---------------------------------------------------------------------------

def test_evaluate_posture_math() -> None:
    o = AIOversight()
    # unwatched: registered impossible without a session, so check ledger scope
    rep = o.report(1)
    assert rep.posture == POSTURE_UNWATCHED and rep.verify()
    # adequate: all adequate
    o.oversee("s-adequate", 2, outcome=OUTCOME_ADEQUATE)
    o.oversee("s-adequate", 3, outcome=OUTCOME_ADEQUATE)
    assert o.evaluate("s-adequate", 4).posture == POSTURE_ADEQUATE
    # not-assessed: any not-assessed, no inadequate/inconclusive
    o.oversee("s-na", 5, outcome=OUTCOME_ADEQUATE)
    o.oversee("s-na", 6, outcome=OUTCOME_NOT_ASSESSED)
    assert o.evaluate("s-na", 7).posture == POSTURE_NOT_ASSESSED
    # contested: any inconclusive outranks not-assessed
    o.oversee("s-con", 8, outcome=OUTCOME_NOT_ASSESSED)
    o.oversee("s-con", 9, outcome=OUTCOME_INCONCLUSIVE)
    assert o.evaluate("s-con", 10).posture == POSTURE_CONTESTED
    # oversight-lapsed: any inadequate outranks everything
    o.oversee("s-lap", 11, outcome=OUTCOME_ADEQUATE)
    o.oversee("s-lap", 12, outcome=OUTCOME_INCONCLUSIVE)
    o.oversee("s-lap", 13, outcome=OUTCOME_INADEQUATE)
    assert o.evaluate("s-lap", 14).posture == POSTURE_OVERSIGHT_LAPSED
    # tallies
    evl = o.evaluate("s-lap", 15)
    assert evl.oversight_count == 3
    assert evl.inadequate_count == 1
    assert evl.inconclusive_count == 1
    assert evl.adequate_count == 1
    assert evl.verify()


    # unknown system refused fail-closed
    with pytest.raises(UnknownSystemError):
        o.evaluate("ghost", 16)


# ---------------------------------------------------------------------------
# 8. evaluate/report read purity
# ---------------------------------------------------------------------------

def test_read_purity() -> None:
    o = AIOversight()
    o.oversee("sys-1", 1, outcome=OUTCOME_ADEQUATE)
    before = len(o.audit_log(100))
    seq0 = o.stats(100)["seq"]
    r1 = o.evaluate("sys-1", 50)
    r2 = o.evaluate("sys-1", 50)  # same read-seq twice is fine
    assert r1.digest == r2.digest
    v = o.verify("ovr-1", 60)
    assert v.verdict == "verified"
    assert o.stats(100)["seq"] == seq0  # reads never consume
    assert len(o.audit_log(100)) == before  # reads emit no rows
    rep = o.report(70, "sys-1")
    assert rep.posture == POSTURE_ADEQUATE and rep.verify()


# ---------------------------------------------------------------------------
# 9. retire terminality + id non-recycling + bad reason + post-retire reads
# ---------------------------------------------------------------------------

def test_retire_terminality() -> None:
    o = AIOversight()
    o.oversee("sys-1", 1, outcome=OUTCOME_ADEQUATE)
    with pytest.raises(BadReasonError):
        o.retire("sys-1", 2, reason="bogus")
    ret = o.retire("sys-1", 3, reason="decommissioned")
    assert ret.verify()
    assert "sys-1" in o.retired_ids(100)
    with pytest.raises(RetiredSystemError):
        o.oversee("sys-1", 4)
    with pytest.raises(RetiredSystemError):
        o.retire("sys-1", 5)  # double-retire refused, id never recycled
    # post-retire reads still work
    evl = o.evaluate("sys-1", 6)
    assert evl.posture == POSTURE_ADEQUATE
    v = o.verify("ovr-1", 7)
    assert v.verdict == "verified"
    with pytest.raises(UnknownSystemError):
        o.retire("ghost", 8)


# ---------------------------------------------------------------------------
# 10. seq discipline: rewind bare, malformed seqs, failed burn
# ---------------------------------------------------------------------------

def test_seq_discipline() -> None:
    o = AIOversight()
    for bad in (True, -1, "1", 1.5, None):
        with pytest.raises(SeqOrderError):
            o.oversee("sys-1", bad)
        with pytest.raises(SeqOrderError):
            o.evaluate("sys-1", bad)
        with pytest.raises(SeqOrderError):
            o.verify("ovr-1", bad)
        with pytest.raises(SeqOrderError):
            o.report(bad)
    assert o.stats(100)["seq"] == -1  # malformed seqs burn nothing
    o.oversee("sys-1", 1)
    with pytest.raises(SeqOrderError):
        o.oversee("sys-1", 1)  # rewind: bare, no row
    assert o.stats(100)["seq"] == 1


# ---------------------------------------------------------------------------
# 11. audit shapes + leak ban + bad-kind
# ---------------------------------------------------------------------------

def test_audit_shapes_and_leak_ban() -> None:
    o = AIOversight()
    o.oversee("sys-1", 1, oversight_kind=KIND_SPOT_CHECK,
              outcome=OUTCOME_ADEQUATE)
    o.retire("sys-1", 2)
    events = o.audit_log(100)
    kinds = [e["kind"] for e in events]
    assert kinds == ["overseen", "retired"]
    for e in events:
        assert e["schema"] == "audit.ndjson/1"
        assert e["version"] == AI_OVERSIGHT_VERSION
    # banned raw-material keys never cross the audit boundary
    with pytest.raises(AuditKindError):
        ai_oversight_audit_event("overseen", 3, transcript="raw text")
    with pytest.raises(AuditKindError):
        ai_oversight_audit_event("retired", 3, weights=b"w")
    with pytest.raises(AuditKindError):
        ai_oversight_audit_event("bogus", 3)
    ev = ai_oversight_audit_event("overseen", 3, oversight_id="ovr-1")
    assert ev["kind"] == "overseen"


# ---------------------------------------------------------------------------
# 12. cross-instance determinism + tamper breaks verify + integrity flip
# ---------------------------------------------------------------------------

def test_determinism_and_tamper() -> None:
    def build() -> AIOversight:
        o = AIOversight()
        o.oversee("sys-1", 1, oversight_kind=KIND_DEEP_REVIEW,
                  outcome=OUTCOME_ADEQUATE,
                  oversight_digest=_good_digest())
        return o

    a, b = build(), build()
    ra = a.oversight_record("ovr-1", 10)
    rb = b.oversight_record("ovr-1", 10)
    assert ra.digest == rb.digest
    # tamper flips verify() as data (never raises)
    object.__setattr__(ra, "outcome", OUTCOME_INADEQUATE)
    assert ra.verify() is False
    v = a.verify("ovr-1", 11)
    assert v.verdict == "tampered" and v.integrity_ok is False
    evl = a.evaluate("sys-1", 12)
    assert evl.integrity_ok is False
    assert evl.posture == POSTURE_OVERSIGHT_LAPSED  # tamper is data
    with pytest.raises(UnknownOversightError):
        a.verify("ovr-999", 13)


# ---------------------------------------------------------------------------
# 13. views/stats + unknown lookups + 8-thread read smoke
# ---------------------------------------------------------------------------

def test_views_stats_threads() -> None:
    o = AIOversight()
    o.oversee("sys-1", 1, oversight_kind=KIND_HUMAN_IN_THE_LOOP,
              outcome=OUTCOME_ADEQUATE)
    o.oversee("sys-2", 2, oversight_kind=KIND_HUMAN_ON_THE_LOOP,
              outcome=OUTCOME_INCONCLUSIVE)
    assert o.system_ids(10) == ("sys-1", "sys-2")
    assert o.oversight_ids(10) == ("ovr-1", "ovr-2")
    assert o.sessions_for("sys-1", 10) == ("ovr-1",)
    assert o.retired_ids(10) == ()
    st = o.stats(10)
    assert st["systems"] == 2 and st["sessions"] == 2 and st["seq"] == 2
    with pytest.raises(UnknownSystemError):
        o.sessions_for("ghost", 10)
    with pytest.raises(UnknownOversightError):
        o.oversight_record("ovr-999", 10)

    errors: list = []

    def reader() -> None:
        try:
            for _ in range(50):
                assert o.evaluate("sys-1", 99).posture == POSTURE_ADEQUATE
                assert o.report(99).posture == POSTURE_CONTESTED
        except Exception as exc:  # pragma: no cover - must not happen
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


# ---------------------------------------------------------------------------
# 14. report whole-ledger scope
# ---------------------------------------------------------------------------

def test_report_whole_ledger_scope() -> None:
    o = AIOversight()
    o.oversee("sys-1", 1, outcome=OUTCOME_ADEQUATE)
    o.oversee("sys-2", 2, outcome=OUTCOME_INADEQUATE)
    o.oversee("sys-3", 3, outcome=OUTCOME_NOT_ASSESSED)
    rep = o.report(10)
    assert rep.system_id == ""
    assert rep.posture == POSTURE_OVERSIGHT_LAPSED
    assert rep.oversight_count == 3
    assert rep.adequate_count == 1
    assert rep.inadequate_count == 1
    assert rep.not_assessed_count == 1
    assert rep.verify()
    with pytest.raises(UnknownSystemError):
        o.report(10, "ghost")


# ---------------------------------------------------------------------------
# 15. main() subprocess check
# ---------------------------------------------------------------------------

def test_main_subprocess() -> None:
    mod_dir = Path(ai_oversight.__file__).parent
    proc = subprocess.run(
        [sys.executable, "ai_oversight.py"],
        cwd=str(mod_dir), capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "ai-oversight OK" in proc.stdout
