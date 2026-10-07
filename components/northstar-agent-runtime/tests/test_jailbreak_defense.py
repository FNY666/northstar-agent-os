"""15 targeted tests for jailbreak_defense.py (house style)."""

import ast
import hashlib
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MODULE = Path(__file__).resolve().parent.parent / "jailbreak_defense.py"


def _load_module():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "jailbreak_defense", str(MODULE))
    module = importlib.util.module_from_spec(spec)
    sys.modules["jailbreak_defense"] = module
    spec.loader.exec_module(module)
    return module


jd = _load_module()

GOOD_PIN = "sha256:" + "ab" * 32


# 1. version / schema pins --------------------------------------------------
def test_version_schema_pins():
    assert jd.VERSION == "jailbreak-defense.v1"
    assert jd.SCHEMA == "northstar.jailbreak-defense.v1"
    assert jd.KIND_DETECTED == "detected"
    assert jd.KIND_BLOCKED == "blocked"
    assert jd.KIND_REPORTED == "reported"
    assert jd.KIND_REJECTED == "rejected"


# 2. stdlib-only AST check ---------------------------------------------------
def test_stdlib_only_ast():
    tree = ast.parse(MODULE.read_text())
    allowed = {
        "hashlib", "re", "threading", "dataclasses", "typing",
        "__future__", "canonical_json", "json",  # json = stdlib fallback
    }
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= allowed, imports - allowed


# 3. detect roundtrip + verify ------------------------------------------------
def test_detect_roundtrip_and_verify():
    ledger = jd.JailbreakDefense()
    record = ledger.detect(
        "p-1", 1, "jailbreak", attack_class="instruction-override",
        score=0.97, prompt_digest=GOOD_PIN)
    assert record.prompt_id == "p-1"
    assert record.verdict == "jailbreak"
    assert record.attack_class == "instruction-override"
    assert record.score == pytest.approx(0.97)
    assert record.digest.startswith("sha256:")
    assert record.verify()
    assert record.as_dict()["schema"] == jd.SCHEMA
    fetched = ledger.detection_record("p-1")
    assert fetched.digest == record.digest


# 4. detect bad-input table + seq-burn + rejected rows ------------------------
def test_detect_bad_inputs_seq_burn_and_rejected_rows():
    ledger = jd.JailbreakDefense()
    base = ledger.rejected_count()
    seq = 1
    bad_cases = [
        ("", 1, "clean", "other", 0.1, ""),          # empty id
        ("p", 1, "nonsense", "other", 0.1, ""),      # bad verdict
        ("p", 1, "clean", "nonsense", 0.1, ""),      # bad attack class
        ("p", 1, "clean", "other", True, ""),        # bool score
        ("p", 1, "clean", "other", float("nan"), ""),  # NaN
        ("p", 1, "clean", "other", float("inf"), ""),  # inf
        ("p", 1, "clean", "other", -0.1, ""),        # out of range
        ("p", 1, "clean", "other", 1.1, ""),         # out of range
        ("p", 1, "clean", "other", "high", ""),      # str score
        ("p", 1, "clean", "other", 0.1, "raw-text"),  # raw digest
        (123, 1, "clean", "other", 0.1, ""),         # non-str id
    ]
    for i, (pid, _s, verdict, cls, score, digest) in enumerate(bad_cases):
        seq = seq + 1
        with pytest.raises(jd.JailbreakDefenseError):
            ledger.detect(pid, seq, verdict, attack_class=cls,
                          score=score, prompt_digest=digest)
    assert ledger.rejected_count() == base + len(bad_cases)
    # failed mutations consumed their seq: next valid seq must advance
    record = ledger.detect("p-ok", seq + 1, "clean", score=0.0)
    assert record.seq == seq + 1
    rejected_kinds = [row["kind"] for row in ledger.audit_log()]
    assert len(rejected_kinds) == len(bad_cases) + 1  # +1 for the success
    assert all(k == jd.KIND_REJECTED for k in rejected_kinds[:-1])


# 5. duplicate detection refused ----------------------------------------------
def test_duplicate_detection_refused():
    ledger = jd.JailbreakDefense()
    ledger.detect("p-dup", 1, "suspicious", score=0.6)
    with pytest.raises(jd.DuplicatePromptError):
        ledger.detect("p-dup", 2, "jailbreak", score=0.9)


# 6. block roundtrip + verify --------------------------------------------------
def test_block_roundtrip_and_verify():
    ledger = jd.JailbreakDefense()
    ledger.detect("p-block", 1, "jailbreak", score=0.99)
    record = ledger.block("p-block", 2, reason="jailbreak-detected")
    assert record.prompt_id == "p-block"
    assert record.reason == "jailbreak-detected"
    assert record.verify()
    assert record.as_dict()["schema"] == jd.SCHEMA
    assert ledger.is_blocked("p-block")
    assert ledger.blocked_ids() == ("p-block",)
    assert ledger.block_record("p-block").digest == record.digest


# 7. block unknown prompt + bad reason -----------------------------------------
def test_block_unknown_and_bad_reason():
    ledger = jd.JailbreakDefense()
    with pytest.raises(jd.UnknownPromptError):
        ledger.block("p-ghost", 1, reason="manual")
    ledger.detect("p-x", 2, "clean", score=0.0)
    with pytest.raises(jd.BadReasonError):
        ledger.block("p-x", 3, reason="nonsense")
    assert ledger.rejected_count() == 2


# 8. double block refused ------------------------------------------------------
def test_double_block_refused():
    ledger = jd.JailbreakDefense()
    ledger.detect("p-twice", 1, "jailbreak", score=0.95)
    ledger.block("p-twice", 2, reason="manual")
    with pytest.raises(jd.AlreadyBlockedError):
        ledger.block("p-twice", 3, reason="manual")


# 9. seq discipline --------------------------------------------------------------
def test_seq_discipline():
    ledger = jd.JailbreakDefense()
    with pytest.raises(jd.SeqOrderError):  # rewind raises bare, no consume
        ledger.detect("p-r", 0, "clean", score=0.0)
    with pytest.raises(jd.SeqOrderError):  # bool seq
        ledger.detect("p-r", True, "clean", score=0.0)
    with pytest.raises(jd.SeqOrderError):  # str seq
        ledger.detect("p-r", "1", "clean", score=0.0)
    assert ledger.stats()["seq"] == 0
    assert ledger.rejected_count() == 0  # bare raises book no rejected row
    ledger.detect("p-r", 1, "clean", score=0.0)
    with pytest.raises(jd.SeqOrderError):  # not strictly greater
        ledger.detect("p-r2", 1, "clean", score=0.0)
    assert ledger.stats()["seq"] == 1


# 10. report aggregate semantics + verify -----------------------------------------
def test_report_aggregate_semantics_and_verify():
    ledger = jd.JailbreakDefense()
    ledger.detect("p-1", 1, "jailbreak", score=0.9)
    ledger.detect("p-2", 2, "suspicious", score=0.55)
    ledger.detect("p-3", 3, "clean", score=0.05)
    ledger.detect("p-4", 4, "jailbreak", score=0.8)
    ledger.block("p-1", 5, reason="jailbreak-detected")
    report = ledger.report(6)
    assert report.detections == 4
    assert report.verdict_count("jailbreak") == 2
    assert report.verdict_count("suspicious") == 1
    assert report.verdict_count("clean") == 1
    assert report.blocked == 1
    assert report.blocked_prompt_ids == ("p-1",)
    assert report.verify()
    assert report.as_dict()["verdict_counts"][2]["verdict"] == "jailbreak"


# 11. report pure-read semantics ---------------------------------------------------
def test_report_pure_read_semantics():
    ledger = jd.JailbreakDefense()
    ledger.detect("p-1", 1, "clean", score=0.0)
    before = len(ledger.audit_log())
    seq_before = ledger.stats()["seq"]
    first = ledger.report(2)
    second = ledger.report(2)  # same seq twice is fine
    assert first.digest == second.digest
    assert len(ledger.audit_log()) == before  # no audit rows written
    assert ledger.stats()["seq"] == seq_before  # seq not consumed


# 12. empty report ------------------------------------------------------------------
def test_empty_report():
    ledger = jd.JailbreakDefense()
    report = ledger.report(1)
    assert report.detections == 0
    assert report.blocked == 0
    assert report.verdict_count("jailbreak") == 0
    assert report.verify()


# 13. audit shapes + leak ban + bad-kind ----------------------------------------------
def test_audit_shapes_leak_ban_and_bad_kind():
    ledger = jd.JailbreakDefense()
    ledger.detect("p-a", 1, "suspicious", score=0.6, prompt_digest=GOOD_PIN)
    rows = ledger.audit_log()
    assert rows[0]["format"] == "audit.ndjson/1"
    assert rows[0]["kind"] == "detected"
    assert rows[0]["detail"]["prompt_digest"] == GOOD_PIN
    blob = str(rows)
    for banned in ("secret prompt text",):
        assert banned not in blob
    for banned_key in ("prompt", "text", "content", "message", "raw",
                       "payload", "value", "input", "user_input"):
        with pytest.raises(jd.JailbreakDefenseError):
            jd.jailbreak_defense_audit_event(
                "detected", **{banned_key: "raw prompt"})
    with pytest.raises(jd.AuditKindError):
        jd.jailbreak_defense_audit_event("nonsense")
    event = jd.jailbreak_defense_audit_event(
        "blocked", prompt_id="p-a", reason="manual")
    assert event["kind"] == "blocked"
    assert event["detail"]["reason"] == "manual"


# 14. cross-instance determinism + tamper breaks verify ----------------------------------
def test_cross_instance_determinism_and_tamper():
    first = jd.JailbreakDefense()
    second = jd.JailbreakDefense()
    rec1 = first.detect("p-t", 1, "jailbreak", attack_class="roleplay",
                        score=0.88, prompt_digest=GOOD_PIN)
    rec2 = second.detect("p-t", 1, "jailbreak", attack_class="roleplay",
                         score=0.88, prompt_digest=GOOD_PIN)
    assert rec1.digest == rec2.digest  # deterministic across instances
    object.__setattr__(rec1, "score", 0.0)  # tamper
    assert not rec1.verify()
    blk1 = first.block("p-t", 2, reason="manual")
    assert blk1.verify()
    object.__setattr__(blk1, "reason", "jailbreak-detected")
    assert not blk1.verify()


# 15. frozen-ness + concurrency smoke + main() subprocess ----------------------------------
def test_frozen_concurrency_and_main():
    ledger = jd.JailbreakDefense()
    ledger.detect("p-f", 1, "clean", score=0.0)
    record = ledger.detection_record("p-f")
    import dataclasses
    with pytest.raises(dataclasses.FrozenInstanceError):
        record.prompt_id = "p-g"  # frozen dataclass rejects
    def reader():
        for _ in range(200):
            ledger.report(2)
            ledger.prompt_ids()
            ledger.stats()
    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    proc = subprocess.run(
        [sys.executable, str(MODULE)], capture_output=True, text=True,
        timeout=30)
    assert proc.returncode == 0, proc.stderr
    assert "jailbreak-defense OK" in proc.stdout
