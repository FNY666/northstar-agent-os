"""Tests for ai_transparency_auditing: 15 targeted tests, house style."""

from __future__ import annotations

import ast
import pathlib
import subprocess
import sys
import threading

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
import ai_transparency_auditing as m  # noqa: E402


def new_ledger() -> m.AITransparencyAuditing:
    return m.AITransparencyAuditing()


# 1. pins / vocabularies ----------------------------------------------------


def test_01_pins_and_vocabularies():
    assert m.AI_TRANSPARENCY_AUDITING_VERSION == "ai-transparency-auditing.v1"
    assert m.SCHEMA_PIN == "northstar.ai-transparency-auditing.v1"
    assert len(m.AUDIT_KINDS) == 8
    assert "disclosure-completeness-audit" in m.AUDIT_KINDS
    assert "documentation-completeness-assessment" in m.AUDIT_KINDS
    assert "model-card-audit" in m.AUDIT_KINDS
    assert "decision-log-audit" in m.AUDIT_KINDS
    assert len(m.AUDIT_VERDICTS) == 5
    assert m.VERIFY_VERDICTS == ("verified", "tampered")
    assert m.POSTURES == (
        "unaudited",
        "opaque",
        "contested",
        "conditionally-transparent",
        "transparency-audited",
    )


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
    rec = led.audit("sys-a", 1, audit_kind="external-transparency-audit",
                    verdict="transparent", severity=10)
    assert rec.audit_id == "aud-1"
    assert rec.verify() is True
    rec2 = led.audit("sys-a", 2)
    assert rec2.audit_id == "aud-2"
    assert rec2.audit_kind == "internal-transparency-audit"
    assert rec2.verdict == "not-audited"
    assert rec2.severity == 0
    with pytest.raises(Exception):
        rec.audit_id = "aud-X"  # frozen dataclass
    rep = led.verify("aud-1", 0)
    assert rep.verdict == "verified"
    assert rep.record_id == "aud-1"


# 4. bad-input table + seq burn + rejected-row accounting + bare rewind ------


def test_04_bad_input_table_seq_burn_rewind():
    led = new_ledger()
    bad = [
        ("", 1, {}, m.BadSystemError),                      # empty system id
        ("sys-b", 2, {"audit_kind": "nope"}, m.BadAuditKindError),
        ("sys-b", 3, {"verdict": "nope"}, m.BadVerdictError),
        ("sys-b", 4, {"severity": 101}, m.BadSeverityError),
        ("sys-b", 5, {"severity": True}, m.BadSeverityError),
        ("sys-b", 6, {"audit_digest": "bad"}, m.BadDigestError),
    ]
    for system_id, seq, kw, exc in bad:
        with pytest.raises(exc):
            led.audit(system_id, seq, **kw)
    # failed mutations consume their seq and book rejected rows
    log = led.audit_log(0)
    rejected = [r for r in log if r["kind"] == "rejected"]
    assert len(rejected) == len(bad)
    # a rewind raises bare (no new row, no consumption)
    n_rows = len(led.audit_log(0))
    with pytest.raises(m.SeqOrderError):
        led.audit("sys-b", 2)
    assert len(led.audit_log(0)) == n_rows
    # retired system: mutations refused
    led.audit("sys-c", 7)
    led.retire("sys-c", 8)
    with pytest.raises(m.RetiredSystemError):
        led.audit("sys-c", 9)


# 5. full 8-kind vocabulary --------------------------------------------------


def test_05_full_kind_vocabulary():
    led = new_ledger()
    for i, kind in enumerate(m.AUDIT_KINDS, start=1):
        rec = led.audit(f"sys-k-{i}", i, audit_kind=kind)
        assert rec.audit_kind == kind
        assert rec.verify() is True


# 6. full 5-verdict vocabulary + tallies + opaque-outranks --------------------


def test_06_full_verdict_vocabulary_and_tallies():
    led = new_ledger()
    for i, verdict in enumerate(m.AUDIT_VERDICTS, start=1):
        led.audit("sys-v", i, verdict=verdict)
    ev = led.evaluate("sys-v", 0)
    tallies = dict(ev.tallies)
    for verdict in m.AUDIT_VERDICTS:
        assert tallies[verdict] == 1
    assert ev.posture == "opaque"  # opaque outranks the rest


# 7. verify semantics + tamper-as-data + unknown + read purity ---------------


def test_07_verify_semantics_tamper_unknown_purity():
    led = new_ledger()
    rec = led.audit("sys-t", 1, verdict="transparent")
    assert led.verify("aud-1", 0).verdict == "verified"
    object.__setattr__(led._audits["aud-1"], "severity", 99)  # simulate tamper
    assert led.verify("aud-1", 0).verdict == "tampered"
    with pytest.raises(m.UnknownAuditError):
        led.verify("aud-999", 0)
    with pytest.raises(m.BadSystemError):
        led.verify("", 0)
    n = len(led.audit_log(0))
    led.verify("aud-1", 0)
    led.verify("aud-1", 0)
    assert len(led.audit_log(0)) == n  # pure read: no rows


# 8. evaluate posture ladder (all 4 reachable postures + precedence) ---------


def test_08_evaluate_posture_ladder():
    led = new_ledger()
    led.audit("s-opaque", 1, verdict="opaque")
    led.audit("s-opaque", 2, verdict="inconclusive")
    assert led.evaluate("s-opaque", 0).posture == "opaque"
    led.audit("s-contested", 3, verdict="inconclusive")
    led.audit("s-contested", 4, verdict="transparent")
    assert led.evaluate("s-contested", 0).posture == "contested"
    led.audit("s-cond", 5, verdict="conditional")
    assert led.evaluate("s-cond", 0).posture == "conditionally-transparent"
    led.audit("s-cond", 6, verdict="not-audited")
    assert led.evaluate("s-cond", 0).posture == "conditionally-transparent"
    led.audit("s-ok", 7, verdict="transparent")
    led.audit("s-ok", 8, verdict="transparent")
    assert led.evaluate("s-ok", 0).posture == "transparency-audited"
    with pytest.raises(m.UnknownSystemError):
        led.evaluate("s-unknown", 0)


# 9. evaluate purity + tamper flips integrity_ok -----------------------------


def test_09_evaluate_purity_and_integrity_flip():
    led = new_ledger()
    led.audit("sys-e", 1, verdict="transparent")
    ev = led.evaluate("sys-e", 0)
    assert ev.integrity_ok is True
    assert ev.verify() is True
    n = len(led.audit_log(0))
    led.evaluate("sys-e", 0)
    assert len(led.audit_log(0)) == n  # pure read: no rows
    object.__setattr__(led._audits["aud-1"], "severity", 99)  # tamper
    assert led.evaluate("sys-e", 0).integrity_ok is False


# 10. retire terminality (bad reason, double, unknown, id non-recycling) -----


def test_10_retire_terminality():
    led = new_ledger()
    led.audit("sys-r", 1, verdict="transparent")
    with pytest.raises(m.BadReasonError):
        led.retire("sys-r", 2, reason="nope")
    with pytest.raises(m.UnknownSystemError):
        led.retire("sys-ghost", 3)
    rec = led.retire("sys-r", 4, reason="manual")
    assert rec.verify() is True
    with pytest.raises(m.RetiredSystemError):
        led.retire("sys-r", 5)  # double retire
    with pytest.raises(m.RetiredSystemError):
        led.audit("sys-r", 6)  # post-retire mutations refused
    # reads still work after retire
    assert led.evaluate("sys-r", 0).posture == "transparency-audited"
    assert led.audit_record("aud-1", 0).verdict == "transparent"


# 11. seq discipline (genesis, malformed, gaps, read seqs) -------------------


def test_11_seq_discipline():
    led = new_ledger()
    with pytest.raises(m.BadSeqError):
        led.audit("sys-s", 0)  # genesis must be >= 1
    with pytest.raises(m.BadSeqError):
        led.audit("sys-s", True)
    with pytest.raises(m.BadSeqError):
        led.audit("sys-s", 1.5)
    rec = led.audit("sys-s", 5)  # gap seqs allowed (strictly increasing)
    assert rec.seq == 5
    with pytest.raises(m.SeqOrderError):
        led.audit("sys-s", 5)  # not strictly increasing: bare rewind
    assert led.verify("aud-1", 0).verdict == "verified"  # read seqs: any shape
    with pytest.raises(m.BadSeqError):
        led.evaluate("sys-s", -1)


# 12. audit shapes + leak ban + bad builder kind -----------------------------


def test_12_audit_shapes_leak_ban_bad_kind():
    led = new_ledger()
    led.audit("sys-l", 1, audit_kind="disclosure-completeness-audit", verdict="conditional", severity=42)
    row = led.audit_log(0)[0]
    assert row["module"] == "ai_transparency_auditing"
    assert row["version"] == "ai-transparency-auditing.v1"
    assert row["schema"] == "audit.ndjson/1"
    assert row["kind"] == "audited"
    assert row["details"]["audit_kind"] == "disclosure-completeness-audit"
    assert row["details"]["severity"] == 42  # declared scalar, emittable
    for banned in ("transparency_workpaper", "model_card", "datasheet",
                   "decision_log", "data_provenance", "transparency_evidence",
                   "interview_notes", "transcript", "weights"):
        with pytest.raises(m.AuditKeyError):
            m.ai_transparency_auditing_audit_event("audited", 2, {banned: "x"})
    with pytest.raises(m.AuditKindError):
        m.ai_transparency_auditing_audit_event("nope", 2, {})
    with pytest.raises(m.BadSeqError):
        m.ai_transparency_auditing_audit_event("audited", -1, {})


# 13. views / stats / unknown lookups ----------------------------------------


def test_13_views_stats_unknown_lookups():
    led = new_ledger()
    led.audit("sys-a1", 1, verdict="transparent")
    led.audit("sys-a1", 2, verdict="conditional")
    led.audit("sys-a2", 3, verdict="opaque")
    assert led.audits_for("sys-a1", 0) == ("aud-1", "aud-2")
    assert led.audits_for("sys-ghost", 0) == ()
    assert led.system_ids(0) == ("sys-a1", "sys-a2")
    assert led.audit_ids(0) == ("aud-1", "aud-2", "aud-3")
    assert led.retired_ids(0) == ()
    led.retire("sys-a1", 4)
    assert led.retired_ids(0) == ("sys-a1",)
    stats = led.stats(0)
    assert stats == {"module": "ai-transparency-auditing.v1", "n_audits": 3,
                     "n_systems": 2, "n_retired": 1, "last_seq": 4}
    with pytest.raises(m.UnknownAuditError):
        led.audit_record("aud-999", 0)
    with pytest.raises(m.UnknownSystemError):
        led.retire_record("sys-ghost", 0)


# 14. cross-instance determinism + 8-thread read smoke + frozen-ness ----------


def test_14_determinism_thread_smoke_frozen():
    led1, led2 = new_ledger(), new_ledger()
    r1 = led1.audit("sys-d", 1, audit_kind="documentation-completeness-assessment", verdict="transparent")
    r2 = led2.audit("sys-d", 1, audit_kind="documentation-completeness-assessment", verdict="transparent")
    assert r1.audit_digest == r2.audit_digest  # deterministic digest
    import dataclasses
    with pytest.raises(dataclasses.FrozenInstanceError):
        r1.severity = 5
    errs = []
    def worker(n):
        try:
            for _ in range(50):
                led1.verify("aud-1", 0)
                led1.evaluate("sys-d", 0)
                led1.audit_ids(0)
        except Exception as e:  # noqa: BLE001
            errs.append(e)
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errs


# 15. main() subprocess self-check --------------------------------------------


def test_15_main_subprocess_self_check():
    out = subprocess.run(
        [sys.executable, m.__file__],
        capture_output=True, text=True, timeout=60,
    )
    assert out.returncode == 0
    assert "ai-transparency-auditing OK: audit, verify, evaluate, retire, pins, audit" in out.stdout
