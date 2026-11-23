"""Tests for the ai_prevention decision ledger (Simulated).

House contract: frozen records, caller int seqs strictly increasing
with claim-then-burn, no wall-clock, RLock-guarded, fail-closed
taxonomy, stdlib-only AST-verified, sha256: digest pins, audit.ndjson/1.
"""
from __future__ import annotations

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import ai_prevention
from ai_prevention import (
    AI_PREVENTION_VERSION,
    SCHEMA_PIN,
    AIPrevention,
    AIPreventionError,
    AuditKindError,
    BadDigestError,
    BadPreventionKindError,
    BadReasonError,
    BadStatusError,
    BadThreatError,
    POSTURES,
    PREVENTION_KINDS,
    RETIRE_REASONS,
    STATUSES,
    RetiredThreatError,
    SeqOrderError,
    UnknownPreventionError,
    UnknownThreatError,
    ai_prevention_audit_event,
    stdlib_only,
)

GOOD_DIGEST = "sha256:" + "ab" * 32


def test_pins_and_vocabularies():
    """Version/schema pins and pinned vocabularies are exact."""
    assert AI_PREVENTION_VERSION == "ai-prevention.v1"
    assert SCHEMA_PIN == "northstar.ai-prevention.v1"
    assert PREVENTION_KINDS == (
        "access-control",
        "input-filtering",
        "output-filtering",
        "capability-gating",
        "deployment-guardrail",
        "data-lineage-control",
        "model-hardening",
        "rate-limiting",
    )
    assert STATUSES == ("deployed", "pending", "failed", "bypassed")
    assert POSTURES == (
        "unprotected",
        "insufficient",
        "contested",
        "partially-prevented",
        "prevented",
    )
    assert RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")


def test_stdlib_only():
    """AST self-check: only stdlib (plus canonical_json fallback) is imported."""
    assert stdlib_only()
    path = Path(ai_prevention.__file__)
    tree = ast.parse(path.read_text())
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


def test_prevent_happy_path_mints_ids_registers_threat():
    """prevent() mints prv-N ids, registers the threat, and pins digests."""
    ledger = AIPrevention()
    r1 = ledger.prevent(
        "threat-1",
        1,
        prevention_kind="input-filtering",
        status="deployed",
        threat_digest=GOOD_DIGEST,
    )
    assert r1.prevention_id == "prv-1"
    assert r1.threat_id == "threat-1"
    assert r1.seq == 1
    assert r1.prevention_kind == "input-filtering"
    assert r1.status == "deployed"
    assert r1.threat_digest == GOOD_DIGEST
    assert r1.digest.startswith("sha256:") and len(r1.digest) == 71
    assert r1.verify()
    r2 = ledger.prevent("threat-1", 2, prevention_kind="output-filtering")
    assert r2.prevention_id == "prv-2"
    assert r2.verify()
    assert ledger.threat_ids(0) == ("threat-1",)
    assert ledger.prevention_ids(0) == ("prv-1", "prv-2")
    recs = ledger.preventions_for("threat-1", 0)
    assert tuple(r.prevention_id for r in recs) == ("prv-1", "prv-2")


def test_prevent_defaults_and_digest_pin():
    """Defaults are access-control/deployed; digest pins re-derive."""
    ledger = AIPrevention()
    rec = ledger.prevent("threat-d", 1)
    assert rec.prevention_kind == "access-control"
    assert rec.status == "deployed"
    assert rec.threat_digest == ""
    assert rec.verify()
    # deterministic pin: same inputs reproduce the same digest
    ledger2 = AIPrevention()
    rec2 = ledger2.prevent("threat-d", 1)
    assert rec2.digest == rec.digest


def test_prevent_bad_kind_burns_seq_books_rejected():
    """Bad prevention_kind consumes the seq and books a rejected row."""
    ledger = AIPrevention()
    before = len(ledger.audit_log(0))
    with pytest.raises(BadPreventionKindError):
        ledger.prevent("threat-b", 1, prevention_kind="water-cannon")
    rows = ledger.audit_log(0)
    assert len(rows) == before + 1
    row = rows[-1]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-prevention"
    assert row["kind"] == "rejected"
    assert row["seq"] == 1
    assert row["details"]["rejected_kind"] == "BadPreventionKindError"
    # burned seq is consumed: reusing 1 raises bare SeqOrderError
    with pytest.raises(SeqOrderError):
        ledger.prevent("threat-b", 1, prevention_kind="access-control")
    # ledger still usable on the next seq
    rec = ledger.prevent("threat-b", 2, prevention_kind="access-control")
    assert rec.prevention_id == "prv-1"


def test_prevent_bad_status_bad_digest_rejected():
    """Bad status / bad digest fail closed and burn their seqs."""
    ledger = AIPrevention()
    with pytest.raises(BadStatusError):
        ledger.prevent("threat-s", 1, status="mostly-deployed")
    with pytest.raises(BadDigestError):
        ledger.prevent("threat-s", 2, threat_digest="not-a-digest")
    with pytest.raises(BadDigestError):
        ledger.prevent("threat-s", 3, threat_digest="sha256:" + "zz" * 32)
    rejected = [r for r in ledger.audit_log(0) if r["kind"] == "rejected"]
    assert [r["seq"] for r in rejected] == [1, 2, 3]
    assert ledger.stats(0)["n_preventions"] == 0


def test_prevent_bad_threat_id_rejected():
    """Empty / non-string threat ids fail closed."""
    ledger = AIPrevention()
    for bad, seq in (("", 1), ("   ", 2), (None, 3), (True, 4), (123, 5)):
        with pytest.raises(BadThreatError):
            ledger.prevent(bad, seq)
    rejected = [r for r in ledger.audit_log(0) if r["kind"] == "rejected"]
    assert len(rejected) == 5
    assert all(
        r["details"]["rejected_kind"] == "BadThreatError" for r in rejected
    )


def test_seq_rewind_raises_bare_no_burn():
    """Rewinds raise SeqOrderError bare: no burn, no audit row."""
    ledger = AIPrevention()
    ledger.prevent("threat-w", 5)
    before = len(ledger.audit_log(0))
    with pytest.raises(SeqOrderError):
        ledger.prevent("threat-w", 5)
    with pytest.raises(SeqOrderError):
        ledger.prevent("threat-w", 3)
    with pytest.raises(SeqOrderError):
        ledger.prevent("threat-w", True)
    assert len(ledger.audit_log(0)) == before


def test_verify_verified_report_pins():
    """verify() on a clean record: verdict verified, pins re-derive."""
    ledger = AIPrevention()
    rec = ledger.prevent("threat-v", 1, prevention_kind="rate-limiting")
    before = len(ledger.audit_log(0))
    rep = ledger.verify(rec.prevention_id, 99)
    assert rep.record_id == rec.prevention_id
    assert rep.seq == 99
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify()
    # pure read: no audit row, seq not consumed
    assert len(ledger.audit_log(0)) == before
    rep2 = ledger.verify(rec.prevention_id, 99)
    assert rep2.digest == rep.digest
    # unknown ids and bad read seqs refused
    with pytest.raises(UnknownPreventionError):
        ledger.verify("prv-999", 3)
    with pytest.raises(UnknownPreventionError):
        ledger.verify("", 3)
    with pytest.raises(SeqOrderError):
        ledger.verify(rec.prevention_id, "two")


def test_verify_tamper_as_data():
    """Tampering a record flips the verdict to tampered as data, never raised."""
    ledger = AIPrevention()
    rec = ledger.prevent("threat-t", 1)
    object.__setattr__(rec, "status", "bypassed")
    rep = ledger.verify(rec.prevention_id, 2)
    assert rep.verdict == "tampered"
    assert rep.integrity_ok is False
    assert rep.verify()
    ev = ledger.evaluate("threat-t", 3)
    assert ev.integrity_ok is False


def test_evaluate_posture_ladder():
    """All 4 reachable postures, with bypassed > failed > pending > deployed."""
    ledger = AIPrevention()
    # prevented: all deployed
    ledger.prevent("thr-a", 1, status="deployed")
    ledger.prevent("thr-a", 2, status="deployed")
    ev = ledger.evaluate("thr-a", 3)
    assert ev.posture == "prevented"
    assert ev.n_preventions == 2 and ev.n_deployed == 2
    assert ev.integrity_ok is True and ev.verify()
    # partially-prevented: any pending
    ledger.prevent("thr-b", 4, status="deployed")
    ledger.prevent("thr-b", 5, status="pending")
    assert ledger.evaluate("thr-b", 6).posture == "partially-prevented"
    # contested: any failed outranks pending
    ledger.prevent("thr-c", 7, status="pending")
    ledger.prevent("thr-c", 8, status="failed")
    assert ledger.evaluate("thr-c", 9).posture == "contested"
    # insufficient: any bypassed outranks everything
    ledger.prevent("thr-d", 10, status="deployed")
    ledger.prevent("thr-d", 11, status="failed")
    ledger.prevent("thr-d", 12, status="bypassed")
    ev = ledger.evaluate("thr-d", 13)
    assert ev.posture == "insufficient"
    assert ev.n_preventions == 3
    assert ev.n_bypassed == 1
    assert ev.n_failed == 1
    assert ev.n_deployed == 1
    assert ev.verify()
    # pure read: no audit row
    before = len(ledger.audit_log(0))
    ledger.evaluate("thr-a", 14)
    assert len(ledger.audit_log(0)) == before


def test_evaluate_unknown_threat_raises():
    """evaluate() on an unknown threat fails closed."""
    ledger = AIPrevention()
    ledger.prevent("threat-e", 1)
    with pytest.raises(UnknownThreatError):
        ledger.evaluate("no-such-threat", 2)
    with pytest.raises(BadThreatError):
        ledger.evaluate("", 2)


def test_retire_terminality():
    """Retired threat ids refuse mutations; ids never recycled; reads still work."""
    ledger = AIPrevention()
    ledger.prevent("threat-r", 1)
    ret = ledger.retire("threat-r", 2, reason="superseded")
    assert ret.verify()
    assert ret.reason == "superseded"
    # post-retire mutation refused (fail-closed), seq burned
    before = len(ledger.audit_log(0))
    with pytest.raises(RetiredThreatError):
        ledger.prevent("threat-r", 3)
    assert len(ledger.audit_log(0)) == before + 1
    assert ledger.audit_log(0)[-1]["kind"] == "rejected"
    # double retire refused, unknown threat refused
    with pytest.raises(RetiredThreatError):
        ledger.retire("threat-r", 4)
    with pytest.raises(UnknownThreatError):
        ledger.retire("never-seen", 5)
    with pytest.raises(BadReasonError):
        ledger.retire("threat-r", 6, reason="exploded")
    # reads still work
    assert ledger.retired_ids(0) == ("threat-r",)
    assert ledger.retire_record("threat-r", 0).verify()
    ev = ledger.evaluate("threat-r", 7)
    assert ev.posture == "prevented"


def test_audit_events_views_and_banned_keys():
    """Audit rows, banned-key boundary, stats and record views."""
    ledger = AIPrevention()
    rec = ledger.prevent("threat-x", 1, prevention_kind="model-hardening")
    rows = ledger.audit_log(0)
    assert len(rows) == 1
    row = rows[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-prevention"
    assert row["version"] == AI_PREVENTION_VERSION
    assert row["kind"] == "prevented"
    assert row["details"]["prevention_id"] == "prv-1"
    assert row["details"]["prevention_kind"] == "model-hardening"
    # banned keys may not cross the audit boundary as raw material
    with pytest.raises(AIPreventionError):
        ai_prevention_audit_event("prevented", 2, prompt="raw prompt text")
    with pytest.raises(AIPreventionError):
        ai_prevention_audit_event("prevented", 2, weights="raw weights")
    with pytest.raises(AIPreventionError):
        ai_prevention_audit_event("prevented", 2, threat_text="raw intel")
    # digest pins of banned values remain fine
    ok = ai_prevention_audit_event(
        "prevented", 2, threat_digest=GOOD_DIGEST
    )
    assert ok["details"]["threat_digest"] == GOOD_DIGEST
    with pytest.raises(AuditKindError):
        ai_prevention_audit_event("exploded", 2)
    # views
    assert ledger.prevention_record("prv-1", 0).verify() == rec.verify()
    assert ledger.stats(0) == {
        "n_threats": 1,
        "n_preventions": 1,
        "n_retired": 0,
        "seq": 1,
        "version": AI_PREVENTION_VERSION,
    }
    assert isinstance(ledger.audit_log(0), tuple)


def test_self_check_and_concurrency():
    """Module main() runs; concurrent prevent() keeps seq discipline and mints ids."""
    proc = subprocess.run(
        [sys.executable, "-m", "ai_prevention"],
        cwd=Path(ai_prevention.__file__).parent,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ai-prevention OK" in proc.stdout

    ledger = AIPrevention()
    errors: list = []
    ids: list = []

    def worker(n: int):
        try:
            rec = ledger.prevent(f"threat-{n}", n)
            ids.append(rec.prevention_id)
        except Exception as exc:  # noqa: BLE001 - smoke test collects failures
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i + 1,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(set(ids)) == 8
    assert ledger.stats(0)["n_preventions"] == 8
