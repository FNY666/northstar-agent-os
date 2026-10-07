"""Tests for ai_safety_auditing: 15 targeted tests, house style."""

from __future__ import annotations

import ast
import pathlib
import subprocess
import sys
import threading

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
import ai_safety_auditing as m  # noqa: E402


def new_ledger() -> m.AISafetyAuditing:
    return m.AISafetyAuditing()


# 1. pins / vocabularies ----------------------------------------------------


def test_01_pins_and_vocabularies():
    assert m.AI_SAFETY_AUDITING_VERSION == "ai-safety-auditing.v1"
    assert m.SCHEMA_PIN == "northstar.ai-safety-auditing.v1"
    assert len(m.AUDIT_KINDS) == 8
    assert len(m.AUDIT_VERDICTS) == 5
    assert m.VERIFY_VERDICTS == ("verified", "tampered")
    assert len(m.POSTURES) == 5


# 2. stdlib-only AST ---------------------------------------------------------


def test_02_stdlib_only_ast():
    assert m.stdlib_only() is True
    tree = ast.parse(pathlib.Path(m.__file__).read_text(encoding="utf-8"))
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            roots.add((node.module or "").split(".")[0])
    roots.discard("canonical_json")  # optional, stdlib fallback present
    assert roots <= {"__future__", "ast", "hashlib", "json", "threading",
                     "dataclasses", "typing", "pathlib"}


# 3. audit roundtrip / aud-N minting / verify / frozen-ness ------------------


def test_03_audit_roundtrip_minting_frozen():
    led = new_ledger()
    rec = led.audit("sys-a", 1, audit_kind="external-audit",
                    verdict="satisfactory", severity=10)
    assert rec.audit_id == "aud-1"
    assert rec.verify() is True
    rec2 = led.audit("sys-a", 2)
    assert rec2.audit_id == "aud-2"
    assert rec2.audit_kind == "internal-audit"  # default
    assert rec2.verdict == "not-audited"  # default
    with pytest.raises(Exception):
        rec.verdict = "unsatisfactory"  # normal assignment is frozen


# 4. bad-input table + seq-burn + rejected-row accounting + rewind ----------


def test_04_bad_input_table_seq_burn_rewind():
    led = new_ledger()
    led.audit("sys-b", 1)  # aud-1, registers sys-b
    n_rejected = 0
    seq = 2
    bad_calls = [
        lambda s: led.audit("", s),  # bad system
        lambda s: led.audit("sys-b", s, audit_kind="bogus"),  # bad kind
        lambda s: led.audit("sys-b", s, verdict="bogus"),  # bad verdict
        lambda s: led.audit("sys-b", s, severity=101),  # bad severity
        lambda s: led.audit("sys-b", s, severity=True),  # bool severity
        lambda s: led.audit("sys-b", s, audit_digest="bogus"),  # bad digest
    ]
    for call in bad_calls:
        with pytest.raises(m.AISafetyAuditingError):
            call(seq)
        n_rejected += 1
        seq += 1
    rejected = [r for r in led.audit_log(0) if r["kind"] == "rejected"]
    assert len(rejected) == n_rejected
    # rewind raises bare, no new row, no consumption
    before = len(led.audit_log(0))
    with pytest.raises(m.SeqOrderError):
        led.audit("sys-b", 1)
    assert len(led.audit_log(0)) == before


# 5. full 8-kind vocabulary --------------------------------------------------


def test_05_full_kind_vocabulary():
    led = new_ledger()
    seq = 0
    for kind in m.AUDIT_KINDS:
        seq += 1
        rec = led.audit(f"sys-{kind}", seq, audit_kind=kind)
        assert rec.audit_kind == kind
        assert rec.verify() is True


# 6. full 5-verdict vocabulary + tallies + precedence -----------------------


def test_06_full_verdict_vocabulary_and_tallies():
    led = new_ledger()
    seq = 0
    for verdict in m.AUDIT_VERDICTS:
        seq += 1
        led.audit("sys-v", seq, verdict=verdict)
    ev = led.evaluate("sys-v", 0)
    tally = dict(ev.tallies)
    assert all(tally[v] == 1 for v in m.AUDIT_VERDICTS)
    assert ev.posture == "unsafe"  # unsatisfactory outranks


# 7. verify semantics + tamper-as-data + unknown refusal + read purity ------


def test_07_verify_semantics_tamper_unknown_purity():
    led = new_ledger()
    rec = led.audit("sys-w", 1)
    rep = led.verify(rec.audit_id, 0)
    assert rep.verdict == "verified"
    before = len(led.audit_log(0))
    rep2 = led.verify(rec.audit_id, 0)  # pure read: no row
    assert len(led.audit_log(0)) == before
    assert rep2.verdict == "verified"
    object.__setattr__(rec, "audit_digest", "sha256:" + "0" * 64)  # tamper as data
    rep3 = led.verify(rec.audit_id, 0)
    assert rep3.verdict == "tampered"
    with pytest.raises(m.UnknownAuditError):
        led.verify("aud-999", 0)
    with pytest.raises(m.BadSeqError):
        led.verify(rec.audit_id, -1)


# 8. evaluate posture ladder --------------------------------------------------


def test_08_evaluate_posture_ladder():
    led = new_ledger()
    s = 0
    s += 1
    led.audit("p-unsafe", s, verdict="unsatisfactory")
    s += 1
    led.audit("p-contested", s, verdict="satisfactory")
    s += 1
    led.audit("p-contested", s, verdict="inconclusive")
    s += 1
    led.audit("p-conditional", s, verdict="satisfactory")
    s += 1
    led.audit("p-conditional", s, verdict="conditional")
    s += 1
    led.audit("p-safe", s, verdict="satisfactory")
    assert led.evaluate("p-unsafe", 0).posture == "unsafe"
    assert led.evaluate("p-contested", 0).posture == "contested"
    assert led.evaluate("p-conditional", 0).posture == "conditionally-safe"
    assert led.evaluate("p-safe", 0).posture == "audited-safe"
    with pytest.raises(m.UnknownSystemError):
        led.evaluate("p-nope", 0)


# 9. evaluate read purity + integrity flip ------------------------------------


def test_09_evaluate_purity_and_integrity_flip():
    led = new_ledger()
    rec = led.audit("sys-i", 1, verdict="satisfactory")
    ev = led.evaluate("sys-i", 0)
    assert ev.integrity_ok is True
    before = len(led.audit_log(0))
    ev2 = led.evaluate("sys-i", 0)
    assert len(led.audit_log(0)) == before  # no rows on reads
    assert ev2.integrity_ok is True
    object.__setattr__(rec, "audit_digest", "sha256:" + "f" * 64)
    ev3 = led.evaluate("sys-i", 0)
    assert ev3.integrity_ok is False


# 10. retire terminality + id non-recycling + post-retire reads --------------


def test_10_retire_terminality():
    led = new_ledger()
    led.audit("sys-r", 1)
    r = led.retire("sys-r", 2, reason="manual")
    assert r.reason == "manual"
    with pytest.raises(m.RetiredSystemError):
        led.retire("sys-r", 3, reason="superseded")  # id never recycled
    with pytest.raises(m.RetiredSystemError):
        led.audit("sys-r", 4)  # post-retire mutations refused
    with pytest.raises(m.BadReasonError):
        led.audit("sys-r2", 5) if False else led.retire("sys-r2", 5, reason="bogus")
    # post-retire reads still work
    rec = led.audit_record("aud-1", 0)
    assert rec.system_id == "sys-r"
    assert led.evaluate("sys-r", 0).posture == "conditionally-safe"  # not-audited default
    assert led.retire_record("sys-r", 0).reason == "manual"


# 11. seq discipline: genesis rewind bare, malformed seqs, burn-on-fail ------


def test_11_seq_discipline():
    led = new_ledger()
    with pytest.raises(m.BadSeqError):
        led.audit("sys-s", 0)  # genesis seq must be >= 1
    with pytest.raises(m.BadSeqError):
        led.audit("sys-s", True)  # bool refused
    with pytest.raises(m.BadSeqError):
        led.audit("sys-s", 1.5)  # float refused
    led.audit("sys-s", 1)
    with pytest.raises(m.SeqOrderError):
        led.audit("sys-s", 1)  # rewind bare
    # failed mutation consumes seq: next valid claim must be > failed seq
    with pytest.raises(m.BadVerdictError):
        led.audit("sys-s", 2, verdict="bogus")  # burns seq 2
    rec = led.audit("sys-s", 3)
    assert rec.audit_id == "aud-2"
    assert rec.seq == 3


# 12. audit shapes + leak ban + bad-kind --------------------------------------


def test_12_audit_shapes_leak_ban_bad_kind():
    ev = m.ai_safety_auditing_audit_event(
        "audited", 1, {"audit_id": "aud-1", "audit_kind": "internal-audit"}
    )
    assert ev["module"] == "ai_safety_auditing"
    assert ev["schema"] == "audit.ndjson/1"
    assert ev["kind"] == "audited"
    assert ev["seq"] == 1
    with pytest.raises(m.AuditKeyError):
        m.ai_safety_auditing_audit_event("audited", 2, {"audit_workpaper": "x"})
    with pytest.raises(m.AuditKeyError):
        m.ai_safety_auditing_audit_event("retired", 3, {"weights": "x"})
    with pytest.raises(m.AuditKindError):
        m.ai_safety_auditing_audit_event("bogus-kind", 4, {})
    with pytest.raises(m.BadSeqError):
        m.ai_safety_auditing_audit_event("audited", -1, {})


# 13. views / stats / unknown lookups ----------------------------------------


def test_13_views_stats_unknown_lookups():
    led = new_ledger()
    led.audit("sys-a", 1)
    led.audit("sys-a", 2)
    led.audit("sys-b", 3)
    assert led.audits_for("sys-a", 0) == ("aud-1", "aud-2")
    assert led.audits_for("sys-zzz", 0) == ()
    assert led.system_ids(0) == ("sys-a", "sys-b")
    assert led.audit_ids(0) == ("aud-1", "aud-2", "aud-3")
    assert led.retired_ids(0) == ()
    st = led.stats(0)
    assert st["n_audits"] == 3 and st["n_systems"] == 2 and st["last_seq"] == 3
    with pytest.raises(m.UnknownAuditError):
        led.audit_record("aud-999", 0)
    with pytest.raises(m.UnknownSystemError):
        led.retire_record("sys-a", 0)
    with pytest.raises(m.BadSeqError):
        led.stats(-1)


# 14. cross-instance determinism + 8-thread read smoke + frozen-ness ----------


def test_14_determinism_thread_smoke_frozen():
    l1 = new_ledger()
    l2 = new_ledger()
    r1 = l1.audit("sys-d", 1, audit_kind="external-audit", verdict="satisfactory")
    r2 = l2.audit("sys-d", 1, audit_kind="external-audit", verdict="satisfactory")
    assert r1.audit_digest == r2.audit_digest  # cross-instance determinism
    errors = []

    def reader():
        try:
            for _ in range(50):
                l1.verify(r1.audit_id, 0)
                l1.evaluate("sys-d", 0)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    with pytest.raises(Exception):
        r1.severity = 99  # normal assignment is frozen


# 15. main() self-check via subprocess ---------------------------------------


def test_15_main_subprocess_self_check():
    result = subprocess.run(
        [sys.executable, m.__file__],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "ai-safety-auditing OK: audit, verify, evaluate, retire, pins, audit" in result.stdout
