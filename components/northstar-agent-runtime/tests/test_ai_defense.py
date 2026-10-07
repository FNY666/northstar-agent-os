"""Tests for the ai-defense defense-operations decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_defense.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_defense", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_defense"] = module
    spec.loader.exec_module(module)
    return module


sa = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert sa.AI_DEFENSE_VERSION == "ai-defense.v1"
    assert sa.SCHEMA_PIN == "northstar.ai-defense.v1"
    assert sa.DEFENSE_KINDS == (
        "input-filtering",
        "output-filtering",
        "adversarial-training",
        "red-teaming",
        "monitoring",
        "isolation",
        "rate-limiting",
        "graceful-degradation",
    )
    assert sa.READINESS == ("ready", "partial", "not-ready", "degraded")
    assert sa.THREAT_KINDS == (
        "prompt-injection",
        "model-extraction",
        "data-poisoning",
        "backdoor-insertion",
        "jailbreak",
        "adversarial-example",
        "supply-chain-compromise",
        "inference-abuse",
    )
    assert sa.DEFENSE_OUTCOMES == ("blocked", "mitigated", "breached", "inconclusive", "not-engaged")
    assert sa.VERIFY_VERDICTS == ("verified", "tampered")
    assert sa.POSTURES == ("unprotected", "breached", "contested", "resilient", "defended")
    assert sa.RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")
    assert sa.AUDIT_KINDS == ("declared", "defended", "retired", "rejected")


# 2. stdlib-only AST check + stdlib_only()
def test_stdlib_only_ast():
    assert sa.stdlib_only() is True
    tree = ast.parse(MOD.read_text())
    allowed = {
        "hashlib", "json", "threading", "dataclasses", "typing",
        "__future__", "ast", "pathlib", "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert node.module.split(".")[0] in allowed


# 3. declare roundtrip + dcl-N minting + verify() + frozen-ness
def test_declare_roundtrip():
    ledger = sa.AIDefense()
    rec = ledger.declare(
        "sys-1", 1, defense_kind="red-teaming", readiness="ready",
        declaration_digest=PIN,
    )
    assert rec.declaration_id == "dcl-1"
    assert rec.system_id == "sys-1"
    assert rec.seq == 1
    assert rec.verify() is True
    rec2 = ledger.declare("sys-2", 2)
    assert rec2.declaration_id == "dcl-2"
    assert rec2.defense_kind == "input-filtering"
    assert rec2.readiness == "not-ready"
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.readiness = "ready"  # type: ignore[misc]


# 4. declare bad-input table + seq-burn + rejected-row accounting + rewind bare
def test_declare_bad_inputs():
    ledger = sa.AIDefense()
    bads = [
        ("", 1, "input-filtering", "ready", PIN),          # empty system id
        (123, 2, "input-filtering", "ready", PIN),         # non-string id
        ("sys-1", 3, "bogus-kind", "ready", PIN),          # bad defense kind
        ("sys-1", 4, "input-filtering", "bogus", PIN),     # bad readiness
        ("sys-1", 5, "input-filtering", "ready", "nope"),  # bad digest
        ("sys-1", 6, "input-filtering", "ready", "sha256:" + "zz" * 32),  # bad hex
        (None, 7, "input-filtering", "ready", PIN),        # None id
        ("sys-1", 8, "input-filtering", True, PIN),        # bool readiness
    ]
    for system_id, seq, kind, readiness, digest in bads:
        with pytest.raises(sa.AIDefenseError):
            ledger.declare(
                system_id, seq, defense_kind=kind, readiness=readiness,
                declaration_digest=digest,
            )
    # claim-then-burn: each failed mutation consumed its seq
    assert ledger.stats(9)["seq"] == 8
    rejected = [r for r in ledger.audit_log(9) if r["kind"] == "rejected"]
    assert len(rejected) == 8
    # rewind raises bare: no seq consumption, no rejected row
    ledger.declare("sys-9", 9)
    n_before = len(ledger.audit_log(10))
    with pytest.raises(sa.SeqOrderError):
        ledger.declare("sys-9", 9)
    assert ledger.stats(10)["seq"] == 9
    assert len(ledger.audit_log(10)) == n_before


# 5. full 8-defense-kind vocabulary
def test_all_defense_kinds_accepted():
    ledger = sa.AIDefense()
    seq = 0
    for i, kind in enumerate(sa.DEFENSE_KINDS):
        seq += 1
        rec = ledger.declare(f"sys-{i}", seq, defense_kind=kind, readiness="partial")
        assert rec.defense_kind == kind
        assert rec.verify() is True
    assert ledger.stats(seq + 1)["n_declarations"] == 8


# 6. defend roundtrip + def-N minting + frozen-ness
def test_defend_roundtrip():
    ledger = sa.AIDefense()
    dcl = ledger.declare("sys-1", 1)
    dfn = ledger.defend(
        "sys-1", 2, threat_kind="jailbreak", outcome="blocked",
        defense_digest=PIN,
    )
    assert dfn.defense_id == "def-1"
    assert dfn.system_id == "sys-1"
    assert dfn.threat_kind == "jailbreak"
    assert dfn.outcome == "blocked"
    assert dfn.verify() is True
    dfn2 = ledger.defend("sys-1", 3)
    assert dfn2.defense_id == "def-2"
    assert dfn2.threat_kind == "prompt-injection"
    assert dfn2.outcome == "not-engaged"
    with pytest.raises(dataclasses.FrozenInstanceError):
        dfn.outcome = "breached"  # type: ignore[misc]


# 7. defend refusal table (unknown system/retired/bad threat/bad outcome/bad digest) + seq-burn
def test_defend_refusals():
    ledger = sa.AIDefense()
    ledger.declare("live", 1)
    ledger.declare("retire-me", 2)
    ledger.retire("retire-me", 3)
    bads = [
        ("ghost", 4, "prompt-injection", "blocked", PIN),   # unknown system
        ("retire-me", 5, "prompt-injection", "blocked", PIN),  # retired system
        ("live", 6, "bogus-threat", "blocked", PIN),        # bad threat kind
        ("live", 7, "prompt-injection", "bogus", PIN),      # bad outcome
        ("live", 8, "prompt-injection", "blocked", "nope"),  # bad digest
    ]
    for system_id, seq, threat, outcome, digest in bads:
        with pytest.raises(sa.AIDefenseError):
            ledger.defend(
                system_id, seq, threat_kind=threat, outcome=outcome,
                defense_digest=digest,
            )
    assert ledger.stats(9)["seq"] == 8
    rejected = [r for r in ledger.audit_log(9) if r["kind"] == "rejected"]
    assert len(rejected) == 5
    with pytest.raises(sa.UnknownSystemError):
        ledger.defend("ghost", 9)
    with pytest.raises(sa.RetiredSystemError):
        ledger.defend("retire-me", 10)


# 8. full 8-threat vocabulary + full 5-outcome vocabulary
def test_threat_and_outcome_vocabularies():
    ledger = sa.AIDefense()
    ledger.declare("vocab-sys", 1)
    seq = 1
    for kind in sa.THREAT_KINDS:
        seq += 1
        dfn = ledger.defend("vocab-sys", seq, threat_kind=kind, outcome="blocked")
        assert dfn.threat_kind == kind
        assert dfn.verify() is True
    for outcome in sa.DEFENSE_OUTCOMES:
        seq += 1
        dfn = ledger.defend("vocab-sys", seq, threat_kind="jailbreak", outcome=outcome)
        assert dfn.outcome == outcome
    assert ledger.stats(seq + 1)["n_defenses"] == 13


# 9. verify semantics: roundtrip + tamper-as-data + unknown refusal + read purity
def test_verify_semantics():
    ledger = sa.AIDefense()
    dcl = ledger.declare("sys-1", 1)
    dfn = ledger.defend("sys-1", 2, threat_kind="jailbreak", outcome="mitigated")
    n_before = len(ledger.audit_log(3))
    rep = ledger.verify(dfn.defense_id, 3)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify() is True
    rep2 = ledger.verify(dcl.declaration_id, 3)  # same read seq twice
    assert rep2.verdict == "verified"
    assert len(ledger.audit_log(3)) == n_before  # reads emit no audit rows
    assert ledger.stats(3)["seq"] == 2  # reads consume no seq
    with pytest.raises(sa.UnknownRecordError):
        ledger.verify("def-999", 3)
    # tamper is reported as data, never raised
    object.__setattr__(dfn, "outcome", "breached")
    tampered = ledger.verify(dfn.defense_id, 4)
    assert tampered.verdict == "tampered"
    assert tampered.integrity_ok is False
    ev = ledger.evaluate("sys-1", 5)
    assert ev.integrity_ok is False


# 10. evaluate posture math: all postures + precedence + unknown refusal
def test_evaluate_posture_math():
    ledger = sa.AIDefense()
    ledger.declare("s-unprotected", 1)                      # no defenses
    ledger.declare("s-breached", 2)
    ledger.defend("s-breached", 3, outcome="blocked")
    ledger.defend("s-breached", 4, outcome="breached")     # breach outranks
    ledger.declare("s-contested", 5)
    ledger.defend("s-contested", 6, outcome="inconclusive")
    ledger.declare("s-resilient", 7)
    ledger.defend("s-resilient", 8, outcome="mitigated")
    ledger.declare("s-defended", 9)
    ledger.defend("s-defended", 10, outcome="blocked")
    ledger.declare("s-idle", 11)
    ledger.defend("s-idle", 12, outcome="not-engaged")     # never engaged
    assert ledger.evaluate("s-unprotected", 13).posture == "unprotected"
    ev = ledger.evaluate("s-breached", 13)
    assert ev.posture == "breached"
    assert ev.n_defenses == 2 and ev.n_breached == 1 and ev.n_blocked == 1
    assert ledger.evaluate("s-contested", 13).posture == "contested"
    assert ledger.evaluate("s-resilient", 13).posture == "resilient"
    assert ledger.evaluate("s-defended", 13).posture == "defended"
    assert ledger.evaluate("s-idle", 13).posture == "unprotected"
    with pytest.raises(sa.UnknownSystemError):
        ledger.evaluate("ghost", 13)


# 11. evaluate read purity + tamper flips integrity_ok
def test_evaluate_read_purity():
    ledger = sa.AIDefense()
    ledger.declare("sys-1", 1)
    ledger.defend("sys-1", 2, outcome="blocked")
    n_before = len(ledger.audit_log(3))
    ev1 = ledger.evaluate("sys-1", 3)
    ev2 = ledger.evaluate("sys-1", 3)  # same read seq twice
    assert ev1.posture == ev2.posture == "defended"
    assert ev1.integrity_ok is True
    assert len(ledger.audit_log(3)) == n_before
    assert ledger.stats(3)["seq"] == 2
    with pytest.raises(sa.SeqOrderError):
        ledger.evaluate("sys-1", -1)


# 12. retire terminality + id non-recycling + bad reason + post-retire reads
def test_retire_terminality():
    ledger = sa.AIDefense()
    ledger.declare("sys-1", 1)
    ledger.defend("sys-1", 2, outcome="blocked")
    ret = ledger.retire("sys-1", 3, reason="decommissioned")
    assert ret.verify() is True
    assert ledger.retired_ids(4) == ("sys-1",)
    with pytest.raises(sa.RetiredSystemError):
        ledger.declare("sys-1", 4)   # ids never recycled
    with pytest.raises(sa.RetiredSystemError):
        ledger.defend("sys-1", 5)
    with pytest.raises(sa.RetiredSystemError):
        ledger.retire("sys-1", 6)    # double retire
    with pytest.raises(sa.BadReasonError):
        ledger.retire("sys-1", 7, reason="bogus")
    with pytest.raises(sa.UnknownSystemError):
        ledger.retire("ghost", 8)
    # reads still work post-retire
    assert ledger.evaluate("sys-1", 9).posture == "defended"
    assert ledger.declaration_record("dcl-1", 9).system_id == "sys-1"
    assert ledger.defense_record("def-1", 9).outcome == "blocked"
    with pytest.raises(sa.UnknownDeclarationError):
        ledger.declaration_record("dcl-999", 9)
    with pytest.raises(sa.UnknownDefenseError):
        ledger.defense_record("def-999", 9)


# 13. seq discipline: malformed seqs + rewind bare + failed-mutation-consumes-seq
def test_seq_discipline():
    ledger = sa.AIDefense()
    for bad_seq in (True, False, "1", 1.5, None):
        with pytest.raises(sa.SeqOrderError):
            ledger.declare("sys-1", bad_seq)
    assert ledger.stats(0)["seq"] == 0
    assert len(ledger.audit_log(0)) == 0  # malformed seqs burn nothing
    ledger.declare("sys-1", 1)
    with pytest.raises(sa.SeqOrderError):
        ledger.defend("sys-1", 1)  # rewind raises bare
    assert ledger.stats(1)["seq"] == 1
    assert len(ledger.audit_log(1)) == 1  # only the declared row
    with pytest.raises(sa.BadThreatKindError):
        ledger.defend("sys-1", 2, threat_kind="bogus")
    assert ledger.stats(2)["seq"] == 2  # failed mutation consumed its seq


# 14. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    ledger = sa.AIDefense()
    ledger.declare("sys-1", 1)
    ledger.defend("sys-1", 2, threat_kind="jailbreak", outcome="blocked")
    rows = ledger.audit_log(3)
    assert [r["kind"] for r in rows] == ["declared", "defended"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == "ai-defense"
        assert row["version"] == "ai-defense.v1"
    declared = rows[0]["details"]
    assert declared["defense_kind"] == "input-filtering"  # pinned vocab emittable
    # raw material keys may not cross the audit boundary
    with pytest.raises(sa.AIDefenseError):
        sa.ai_defense_audit_event("declared", 9, payload="raw-attack-bytes")
    with pytest.raises(sa.AIDefenseError):
        sa.ai_defense_audit_event("defended", 9, config={"firewall": "rules"})
    with pytest.raises(sa.AuditKindError):
        sa.ai_defense_audit_event("bogus", 9)
    with pytest.raises(sa.SeqOrderError):
        sa.ai_defense_audit_event("declared", "9")


# 15. cross-instance digest determinism + 8-thread read smoke + main() subprocess
def test_determinism_threads_and_main():
    def build():
        ledger = sa.AIDefense()
        ledger.declare("sys-1", 1, defense_kind="monitoring", readiness="ready")
        ledger.defend("sys-1", 2, threat_kind="adversarial-example", outcome="blocked")
        return ledger

    l1, l2 = build(), build()
    assert l1.declaration_record("dcl-1", 0).digest == l2.declaration_record("dcl-1", 0).digest
    assert l1.defense_record("def-1", 0).digest == l2.defense_record("def-1", 0).digest
    ledger = build()
    errors = []

    def read_smoke():
        try:
            for _ in range(50):
                ledger.evaluate("sys-1", 3)
                ledger.verify("def-1", 3)
                ledger.defenses_for("sys-1", 3)
                ledger.stats(3)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=read_smoke) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    proc = subprocess.run(
        [sys.executable, str(MOD)], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0
    assert "ai-defense OK: declare, defend, verify, evaluate, retire, pins, audit" in proc.stdout
