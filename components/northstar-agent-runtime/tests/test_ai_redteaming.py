"""Tests for the ai-redteaming exercise decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_redteaming.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_redteaming", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_redteaming"] = module
    spec.loader.exec_module(module)
    return module


rt = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert rt.AI_REDTEAMING_VERSION == "ai-redteaming.v1"
    assert rt.SCHEMA_PIN == "northstar.ai-redteaming.v1"
    assert rt.ATTACK_KINDS == (
        "prompt-injection",
        "jailbreak",
        "model-extraction",
        "data-poisoning",
        "backdoor-trigger",
        "adversarial-example",
        "inference-abuse",
        "supply-chain-attack",
    )
    assert rt.REDTEAM_OUTCOMES == ("exploited", "blocked", "inconclusive", "no-attack", "not-run")
    assert rt.VERIFY_VERDICTS == ("verified", "tampered")
    assert rt.POSTURES == ("untested", "vulnerable", "contested", "resilient", "clean")
    assert rt.RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")
    assert rt.AUDIT_KINDS == ("redteamed", "retired", "rejected")


# 2. stdlib-only AST check
def test_stdlib_only():
    assert rt.stdlib_only()
    tree = ast.parse(MOD.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in {
                    "hashlib", "json", "threading", "dataclasses", "typing",
                    "__future__", "ast", "pathlib", "canonical_json",
                }


# 3. redteam roundtrip + rtm-N minting + frozen-ness
def test_redteam_roundtrip_minting_frozen():
    ledger = rt.AIRedteaming()
    rec = ledger.redteam("sys-1", 1, attack_kind="jailbreak", outcome="blocked", severity=30)
    assert rec.redteam_id == "rtm-1"
    assert rec.verify()
    assert rec.attack_kind == "jailbreak"
    assert rec.outcome == "blocked"
    assert rec.severity == 30
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.outcome = "exploited"  # type: ignore
    rec2 = ledger.redteam("sys-1", 2)
    assert rec2.redteam_id == "rtm-2"
    assert rec2.attack_kind == "prompt-injection"  # default
    assert rec2.outcome == "not-run"  # default


# 4. bad-input table + seq-burn + rejected-row accounting + rewind bare
def test_bad_inputs_burn_seq_and_rejected_rows():
    ledger = rt.AIRedteaming()
    bad = [
        dict(system_id="", seq=1),  # bad id
        dict(system_id="sys-1", seq=2, attack_kind="nope"),  # bad kind
        dict(system_id="sys-1", seq=3, outcome="nope"),  # bad outcome
        dict(system_id="sys-1", seq=4, severity=101),  # bad severity
        dict(system_id="sys-1", seq=5, severity=True),  # bool severity
        dict(system_id="sys-1", seq=6, redteam_digest="bogus"),  # bad digest
    ]
    for kwargs in bad:
        with pytest.raises(rt.AIRedteamingError):
            ledger.redteam(**kwargs)
    # 6 failed mutations => 6 burned seqs => 6 rejected rows, next good seq is 7
    rejected = [r for r in ledger.audit_log(0) if r["kind"] == "rejected"]
    assert len(rejected) == 6
    rec = ledger.redteam("sys-1", 7)
    assert rec.redteam_id == "rtm-1"
    # rewind raises bare SeqOrderError with no new row
    before = len(ledger.audit_log(0))
    with pytest.raises(rt.SeqOrderError):
        ledger.redteam("sys-1", 5)
    assert len(ledger.audit_log(0)) == before


# 5. full attack-kind vocabulary accepted
def test_full_attack_kind_vocabulary():
    ledger = rt.AIRedteaming()
    for i, kind in enumerate(rt.ATTACK_KINDS, start=1):
        rec = ledger.redteam(f"sys-{i}", i, attack_kind=kind)
        assert rec.attack_kind == kind
        assert rec.verify()


# 6. full outcome vocabulary accepted
def test_full_outcome_vocabulary():
    ledger = rt.AIRedteaming()
    for i, outcome in enumerate(rt.REDTEAM_OUTCOMES, start=1):
        rec = ledger.redteam(f"sys-{i}", i, outcome=outcome)
        assert rec.outcome == outcome


# 7. verify semantics: verified, tamper-as-data, unknown refusal, read purity
def test_verify_semantics():
    ledger = rt.AIRedteaming()
    rec = ledger.redteam("sys-1", 1)
    rep = ledger.verify(rec.redteam_id, 5)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    # tamper the stored record's digest -> tampered as data, never raised
    object.__setattr__(rec, "digest", PIN)
    rep2 = ledger.verify(rec.redteam_id, 6)
    assert rep2.verdict == "tampered"
    assert rep2.integrity_ok is False
    # unknown record refused
    with pytest.raises(rt.UnknownRecordError):
        ledger.verify("rtm-999", 7)
    # pure read: no audit row, seq not consumed
    before = len(ledger.audit_log(0))
    ledger.verify(rec.redteam_id, 8)
    assert len(ledger.audit_log(0)) == before
    rec3 = ledger.redteam("sys-1", 9)
    assert rec3.redteam_id == "rtm-2"


# 8. evaluate posture math: all 5 postures + precedence
def test_evaluate_posture_math():
    ledger = rt.AIRedteaming()
    # vulnerable: any exploited outranks everything
    ledger.redteam("a", 1, outcome="exploited")
    ledger.redteam("a", 2, outcome="blocked")
    assert ledger.evaluate("a", 3).posture == "vulnerable"
    # contested: inconclusive when nothing exploited
    ledger.redteam("b", 4, outcome="blocked")
    ledger.redteam("b", 5, outcome="inconclusive")
    assert ledger.evaluate("b", 6).posture == "contested"
    # resilient: all blocked
    ledger.redteam("c", 7, outcome="blocked")
    ledger.redteam("c", 8, outcome="blocked")
    ev = ledger.evaluate("c", 9)
    assert ev.posture == "resilient"
    assert ev.n_redteams == 2 and ev.n_blocked == 2
    # clean: no-attack / not-run only
    ledger.redteam("d", 10, outcome="no-attack")
    ledger.redteam("d", 11, outcome="not-run")
    assert ledger.evaluate("d", 12).posture == "clean"
    # mixed blocked + not-run -> contested (not all blocked, not clean-only)
    ledger.redteam("e", 13, outcome="blocked")
    ledger.redteam("e", 14, outcome="not-run")
    assert ledger.evaluate("e", 15).posture == "contested"
    # tallies + integrity flag
    ev2 = ledger.evaluate("a", 16)
    assert ev2.n_exploited == 1 and ev2.n_blocked == 1
    assert ev2.integrity_ok is True


# 9. evaluate read purity + unknown-system refusal
def test_evaluate_read_purity_and_unknown():
    ledger = rt.AIRedteaming()
    ledger.redteam("sys-1", 1)
    before = len(ledger.audit_log(0))
    ev1 = ledger.evaluate("sys-1", 5)
    ev2 = ledger.evaluate("sys-1", 6)
    assert ev1.posture == ev2.posture
    assert len(ledger.audit_log(0)) == before
    with pytest.raises(rt.UnknownSystemError):
        ledger.evaluate("nope", 7)


# 10. retire terminality + id non-recycling + bad reason + post-retire reads
def test_retire_terminality():
    ledger = rt.AIRedteaming()
    ledger.redteam("sys-1", 1)
    with pytest.raises(rt.BadReasonError):
        ledger.retire("sys-1", 2, reason="nope")
    ret = ledger.retire("sys-1", 3)
    assert ret.verify()
    with pytest.raises(rt.RetiredSystemError):
        ledger.retire("sys-1", 4)
    with pytest.raises(rt.RetiredSystemError):
        ledger.redteam("sys-1", 5)
    # post-retire reads still work
    ev = ledger.evaluate("sys-1", 6)
    assert ev.posture == "not-run" or ev.posture == "clean"
    assert ledger.retired_ids(0) == ("sys-1",)
    assert ledger.redteam_ids(0) == ("rtm-1",)


# 11. seq discipline: genesis rewind, malformed seqs, failed mutation burns
def test_seq_discipline():
    ledger = rt.AIRedteaming()
    # genesis rewind: seq 0 or negative raises bare with zero rows
    with pytest.raises(rt.SeqOrderError):
        ledger.redteam("sys-1", 0)
    assert ledger.audit_log(0) == ()
    # malformed seqs
    for bad_seq in ("1", 1.5, True, None):
        with pytest.raises(rt.SeqOrderError):
            ledger.redteam("sys-1", bad_seq)
    assert ledger.audit_log(0) == ()
    # negative read seq
    ledger.redteam("sys-1", 1)
    with pytest.raises(rt.SeqOrderError):
        ledger.evaluate("sys-1", -1)


# 12. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    ledger = rt.AIRedteaming()
    rec = ledger.redteam("sys-1", 1)
    rows = ledger.audit_log(0)
    assert rows[0]["schema"] == "audit.ndjson/1"
    assert rows[0]["module"] == "ai-redteaming"
    assert rows[0]["version"] == "ai-redteaming.v1"
    assert rows[0]["kind"] == "redteamed"
    assert rows[0]["details"]["attack_kind"] == "prompt-injection"
    # raw attack material banned at the builder
    with pytest.raises(rt.AIRedteamingError):
        rt.ai_redteaming_audit_event("redteamed", 2, payload="rm -rf /")
    with pytest.raises(rt.AIRedteamingError):
        rt.ai_redteaming_audit_event("redteamed", 2, exploit="x")
    with pytest.raises(rt.AuditKindError):
        rt.ai_redteaming_audit_event("nope", 2)


# 13. cross-instance digest determinism + views/stats + unknown lookups
def test_cross_instance_digest_determinism_and_views():
    a = rt.AIRedteaming()
    b = rt.AIRedteaming()
    ra = a.redteam("sys-1", 1, attack_kind="jailbreak", outcome="blocked", severity=30)
    rb = b.redteam("sys-1", 1, attack_kind="jailbreak", outcome="blocked", severity=30)
    assert ra.digest == rb.digest
    assert a.redteam_record("rtm-1", 0).digest == ra.digest
    assert a.redteams_for("sys-1", 0)[0].redteam_id == "rtm-1"
    assert a.system_ids(0) == ("sys-1",)
    assert a.redteam_ids(0) == ("rtm-1",)
    stats = a.stats(0)
    assert stats["n_systems"] == 1 and stats["n_redteams"] == 1
    with pytest.raises(rt.UnknownRedteamError):
        a.redteam_record("rtm-999", 0)


# 14. thread-safety read smoke + frozen-ness
def test_thread_safety_and_frozen():
    ledger = rt.AIRedteaming()
    ledger.redteam("sys-1", 1)
    rec = ledger.redteam_record("rtm-1", 0)
    assert isinstance(rec, rt.RedteamRecord)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.severity = 99  # type: ignore
    errors = []

    def read():
        try:
            for _ in range(50):
                ledger.verify("rtm-1", 2)
                ledger.evaluate("sys-1", 3)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=read) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


# 15. main() subprocess self-check
def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0
    assert proc.stdout.strip() == "ai-redteaming OK: redteam, verify, evaluate, retire, pins, audit"
