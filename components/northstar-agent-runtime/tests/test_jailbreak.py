"""Tests for the jailbreak red-team test ledger (Simulated)."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "jailbreak.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("jailbreak", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["jailbreak"] = module
    spec.loader.exec_module(module)
    return module


jb = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert jb.JAILBREAK_VERSION == "jailbreak.v1"
    assert jb.SCHEMA_PIN == "northstar.jailbreak.v1"
    assert jb.TECHNIQUES == (
        "prompt-injection",
        "roleplay-jailbreak",
        "encoding-obfuscation",
        "multi-turn-coercion",
        "refusal-suppression",
        "context-override",
        "token-smuggling",
        "jailbreak-template",
    )
    assert jb.TARGET_KINDS == ("chat-model", "agent", "tool-interface", "vision-model")
    assert jb.OUTCOMES == ("blocked", "jailbroken", "partial", "inconclusive")
    assert jb.MITIGATION_ACTIONS == (
        "patch-prompt-filter",
        "retrain-alignment",
        "add-guardrail",
        "tighten-policy",
        "monitor",
        "accept-risk",
    )
    assert jb.RETIRE_REASONS == (
        "manual",
        "campaign-complete",
        "target-decommissioned",
        "superseded",
    )
    assert jb.AUDIT_KINDS == ("tested", "evaluated", "mitigated", "retired", "rejected")


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(MOD.read_text())
    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "canonical_json",
    }
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= allowed, imports - allowed


# 3. test() roundtrip + record verify
def test_test_roundtrip():
    j = jb.Jailbreak()
    rec = j.test(
        "JB-1",
        "prompt-injection",
        1,
        target_kind="chat-model",
        target_digest=PIN,
        attempt_digest=PIN2,
        technique_digest=PIN,
    )
    assert rec.attempt_id == "JB-1"
    assert rec.technique == "prompt-injection"
    assert rec.target_kind == "chat-model"
    assert rec.verify()
    assert j.test_record("JB-1", 0).verify()
    rows = j.audit_log(0)
    assert rows[-1]["kind"] == "tested"
    assert rows[-1]["details"]["attempt_id"] == "JB-1"
    assert rows[-1]["details"]["technique"] == "prompt-injection"


# 4. bad-input table + seq-burn + rejected rows
def test_test_bad_inputs_and_seq_burn():
    j = jb.Jailbreak()
    j.test("JB-1", "prompt-injection", 1)
    seq = 2
    with pytest.raises(jb.DuplicateAttemptError):
        j.test("JB-1", "prompt-injection", seq)
    seq += 1
    with pytest.raises(jb.BadIdError):
        j.test("", "prompt-injection", seq)
    seq += 1
    with pytest.raises(jb.BadTechniqueError):
        j.test("JB-2", "mind-control", seq)
    seq += 1
    with pytest.raises(jb.BadTargetError):
        j.test("JB-2", "prompt-injection", seq, target_kind="mainframe")
    seq += 1
    with pytest.raises(jb.BadDigestError):
        j.test("JB-2", "prompt-injection", seq, attempt_digest="nope")
    # every failed mutation consumed its seq and booked a rejected row
    assert j.stats(0)["seq"] == seq
    rows = j.audit_log(0)
    assert len([r for r in rows if r["kind"] == "rejected"]) == 5
    # seq is burned: reusing it rewinds bare with no new row
    with pytest.raises(jb.SeqOrderError):
        j.test("JB-3", "prompt-injection", seq)
    assert len([r for r in j.audit_log(0) if r["kind"] == "rejected"]) == 5


# 5. retired ids never recycled
def test_duplicate_and_retired_id_never_recycled():
    j = jb.Jailbreak()
    j.test("JB-1", "prompt-injection", 1)
    j.retire("JB-1", 2, reason="campaign-complete")
    assert "JB-1" in j.retired_ids(0)
    with pytest.raises(jb.RetiredAttemptError):
        j.test("JB-1", "prompt-injection", 3)
    with pytest.raises(jb.RetiredAttemptError):
        j.retire("JB-1", 4)
    assert j.stats(0)["attempts"] == 1


# 6. full technique + target vocabulary acceptance
def test_full_technique_and_target_vocabulary():
    j = jb.Jailbreak()
    seq = 0
    for i, technique in enumerate(jb.TECHNIQUES):
        seq += 1
        target = jb.TARGET_KINDS[i % len(jb.TARGET_KINDS)]
        rec = j.test(
            f"JB-{i}",
            technique,
            seq,
            target_kind=target,
            target_digest=PIN,
            attempt_digest=PIN2,
        )
        assert rec.verify()
    for i, target_kind in enumerate(jb.TARGET_KINDS):
        seq += 1
        rec = j.test(f"JB-T{i}", "jailbreak-template", seq, target_kind=target_kind)
        assert rec.target_kind == target_kind and rec.verify()
    assert j.stats(0)["attempts"] == len(jb.TECHNIQUES) + len(jb.TARGET_KINDS)


# 7. evaluate roundtrip + minted ids
def test_evaluate_roundtrip_and_minting():
    j = jb.Jailbreak()
    j.test("JB-1", "roleplay-jailbreak", 1, attempt_digest=PIN)
    ev = j.evaluate("JB-1", 2, outcome="blocked", detail_digest=PIN2)
    assert ev.evaluation_id == "evl-1"
    assert ev.attempt_id == "JB-1"
    assert ev.outcome == "blocked"
    assert ev.verify()
    assert j.evaluation_for("JB-1", 0).verify()
    assert j.evaluation_record("evl-1", 0).verify()
    rows = j.audit_log(0)
    assert rows[-1]["kind"] == "evaluated"
    assert rows[-1]["details"]["evaluation_id"] == "evl-1"
    assert rows[-1]["details"]["outcome"] == "blocked"
    st = j.status("JB-1", 0)
    assert st.outcome == "blocked" and st.verify()


# 8. evaluation outcome vocabulary + refusals
def test_evaluate_outcome_vocabulary_and_refusals():
    j = jb.Jailbreak()
    for i, outcome in enumerate(jb.OUTCOMES):
        j.test(f"JB-{i}", "encoding-obfuscation", i * 2 + 1)
        ev = j.evaluate(f"JB-{i}", i * 2 + 2, outcome=outcome)
        assert ev.outcome == outcome
        assert ev.evaluation_id == f"evl-{i + 1}"
    seq = len(jb.OUTCOMES) * 2 + 1
    with pytest.raises(jb.UnknownAttemptError):
        j.evaluate("JB-NOPE", seq, outcome="blocked")
    seq += 1
    with pytest.raises(jb.AlreadyEvaluatedError):
        j.evaluate("JB-0", seq, outcome="blocked")
    seq += 1
    j.test("JB-NEW", "token-smuggling", seq)
    seq += 1
    with pytest.raises(jb.BadOutcomeError):
        j.evaluate("JB-NEW", seq, outcome="escaped")
    seq += 1
    j.retire("JB-NEW", seq, reason="manual")
    seq += 1
    with pytest.raises(jb.RetiredAttemptError):
        j.evaluate("JB-NEW", seq, outcome="blocked")
    rows = j.audit_log(0)
    assert len([r for r in rows if r["kind"] == "rejected"]) == 4


# 9. mitigate chain across all actions
def test_mitigate_chain():
    j = jb.Jailbreak()
    j.test("JB-1", "multi-turn-coercion", 1)
    j.evaluate("JB-1", 2, outcome="jailbroken")
    seq = 2
    for i, action in enumerate(jb.MITIGATION_ACTIONS):
        seq += 1
        rec = j.mitigate("JB-1", action, seq, plan_digest=PIN)
        assert rec.mitigation_id == f"mit-{i + 1}"
        assert rec.action == action
        assert rec.verify()
    chain = j.mitigations_for("JB-1", 0)
    assert len(chain) == len(jb.MITIGATION_ACTIONS)
    assert [m.action for m in chain] == list(jb.MITIGATION_ACTIONS)
    st = j.status("JB-1", 0)
    assert st.n_mitigations == len(jb.MITIGATION_ACTIONS)


# 10. mitigate refusals
def test_mitigate_refusals():
    j = jb.Jailbreak()
    j.test("JB-1", "refusal-suppression", 1)
    seq = 2
    with pytest.raises(jb.UnknownAttemptError):
        j.mitigate("JB-NOPE", "monitor", seq)
    seq += 1
    with pytest.raises(jb.BadActionError):
        j.mitigate("JB-1", "unplug-everything", seq)
    seq += 1
    j.retire("JB-1", seq, reason="target-decommissioned")
    seq += 1
    with pytest.raises(jb.RetiredAttemptError):
        j.mitigate("JB-1", "monitor", seq)
    seq += 1
    with pytest.raises(jb.RetiredAttemptError):
        j.test("JB-1", "refusal-suppression", seq)
    assert len([r for r in j.audit_log(0) if r["kind"] == "rejected"]) == 4


# 11. retire terminality + reads still work
def test_retire_terminality():
    j = jb.Jailbreak()
    j.test("JB-1", "context-override", 1, attempt_digest=PIN)
    j.evaluate("JB-1", 2, outcome="partial")
    j.mitigate("JB-1", "add-guardrail", 3)
    with pytest.raises(jb.BadReasonError):
        j.retire("JB-1", 4, reason="gave-up")
    r = j.retire("JB-1", 5, reason="superseded")
    assert r.verify()
    assert r.reason == "superseded"
    for fn, args in (
        (j.evaluate, ("JB-1", 6)),
        (lambda aid, s: j.mitigate(aid, "monitor", s), ("JB-1", 7)),
        (j.retire, ("JB-1", 8)),
    ):
        with pytest.raises(jb.RetiredAttemptError):
            fn(*args)
    # reads still work after retirement
    st = j.status("JB-1", 0)
    assert st.live is False and st.outcome == "partial" and st.verify()
    assert j.test_record("JB-1", 0).verify()
    assert len(j.mitigations_for("JB-1", 0)) == 1


# 12. seq discipline: rewind bare, malformed seqs, no burn on reads
def test_seq_discipline():
    j = jb.Jailbreak()
    j.test("JB-1", "prompt-injection", 1)
    # rewind raises bare with zero rejected rows
    before = len([r for r in j.audit_log(0) if r["kind"] == "rejected"])
    with pytest.raises(jb.SeqOrderError):
        j.test("JB-2", "prompt-injection", 1)
    assert len([r for r in j.audit_log(0) if r["kind"] == "rejected"]) == before
    # malformed seqs raise bare
    for bad in (True, "2", 2.0, None, -1):
        with pytest.raises(jb.SeqOrderError):
            j.test("JB-2", "prompt-injection", bad)
    assert len([r for r in j.audit_log(0) if r["kind"] == "rejected"]) == before
    # view seqs are shape-validated only, never consumed
    with pytest.raises(jb.SeqOrderError):
        j.status("JB-1", -1)
    s1 = j.status("JB-1", 1)
    s2 = j.status("JB-1", 1)
    assert s1.digest == s2.digest
    assert j.stats(0)["seq"] == 1


# 13. view read-purity
def test_view_read_purity():
    j = jb.Jailbreak()
    j.test("JB-1", "token-smuggling", 1)
    j.evaluate("JB-1", 2, outcome="inconclusive")
    j.mitigate("JB-1", "monitor", 3)
    rows_before = len(j.audit_log(0))
    for _ in range(3):
        j.status("JB-1", 5)
        j.test_record("JB-1", 5)
        j.evaluation_for("JB-1", 5)
        j.mitigations_for("JB-1", 5)
        j.attempt_ids(5)
        j.evaluation_ids(5)
        j.mitigation_ids(5)
        j.evaluated_ids(5)
        j.live_ids(5)
        j.retired_ids(5)
        j.stats(5)
    assert len(j.audit_log(0)) == rows_before
    assert j.stats(0)["seq"] == 3


# 14. audit shapes + leak ban + bad kind
def test_audit_shapes_leak_ban_bad_kind():
    j = jb.Jailbreak()
    j.test("JB-1", "jailbreak-template", 1)
    j.evaluate("JB-1", 2, outcome="blocked")
    j.mitigate("JB-1", "tighten-policy", 3)
    j.retire("JB-1", 4, reason="manual")
    rows = j.audit_log(0)
    kinds = [r["kind"] for r in rows]
    assert kinds == ["tested", "evaluated", "mitigated", "retired"]
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        assert isinstance(r["seq"], int) and r["seq"] >= 0
    # raw attack material is banned at the builder level
    for bad_key in ("prompt", "attack", "exploit", "payload", "transcript"):
        with pytest.raises(jb.AuditKindError):
            jb.jailbreak_audit_event("tested", 1, **{bad_key: "raw-material"})
    with pytest.raises(jb.AuditKindError):
        jb.jailbreak_audit_event("pwned", 1)
    with pytest.raises(jb.SeqOrderError):
        jb.jailbreak_audit_event("tested", -1)


# 15. determinism + tamper + frozen-ness + thread smoke + main()
def test_determinism_tamper_frozen_and_main():
    a = jb.Jailbreak()
    b = jb.Jailbreak()
    a.test("JB-1", "prompt-injection", 1, target_digest=PIN, attempt_digest=PIN2)
    b.test("JB-1", "prompt-injection", 1, target_digest=PIN, attempt_digest=PIN2)
    assert a.test_record("JB-1", 0).digest == b.test_record("JB-1", 0).digest
    # tamper breaks verify() as data
    rec = a.test_record("JB-1", 0)
    object.__setattr__(rec, "technique", "mind-control")
    assert rec.verify() is False
    st = a.status("JB-1", 0)
    assert st.integrity_ok is False
    assert st.verify() is True
    # frozen-ness
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.technique = "prompt-injection"  # noqa: B018
    # 8-thread read smoke
    errors = []

    def _read():
        try:
            for _ in range(50):
                a.status("JB-1", 0)
                a.test_record("JB-1", 0)
                a.stats(0)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=_read) for _ in range(8)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert not errors
    # main() subprocess check
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "jailbreak OK: test, evaluate, mitigate, pins, audit" in proc.stdout
