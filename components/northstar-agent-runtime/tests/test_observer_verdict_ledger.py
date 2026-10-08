"""Tests for the observer-verdict decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "observer_verdict_ledger.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("observer_verdict_ledger", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["observer_verdict_ledger"] = module
    spec.loader.exec_module(module)
    return module


ovl = _load()


def _verdict(ledger, observer_id, seq, verdict="allow", severity=0,
             action_digest=PIN, reason_digest=PIN2):
    return ledger.verdict(observer_id, seq, action_digest, verdict,
                          reason_digest, severity=severity)


# 1. version/schema pins + VERDICTS exact tuple
def test_version_and_schema_pins():
    assert ovl.OBSERVER_VERDICT_LEDGER_VERSION == "observer-verdict-ledger.v1"
    assert ovl.SCHEMA_PIN == "northstar.observer-verdict-ledger.v1"
    assert ovl.VERDICTS == ("allow", "deny", "flag", "escalate", "abstain")
    assert ovl.AUDIT_KINDS == ("verdict", "retired", "rejected")


# 2. stdlib-only AST check
def test_stdlib_only():
    assert ovl.stdlib_only() is True
    tree = ast.parse(MOD.read_text(encoding="utf-8"))
    allowed = {
        "__future__",
        "ast",
        "dataclasses",
        "hashlib",
        "json",
        "pathlib",
        "threading",
        "typing",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert node.module.split(".")[0] in allowed


# 3. verdict roundtrip / obv-1 minting / fields / digest pin / frozen-ness
def test_verdict_roundtrip():
    ledger = ovl.ObserverVerdictLedger()
    rec = _verdict(ledger, "obs-1", 1, verdict="deny", severity=42)
    assert rec.verdict_id == "obv-1"
    assert rec.observer_seq == 1
    assert rec.observer_id == "obs-1"
    assert rec.action_digest == PIN
    assert rec.verdict == "deny"
    assert rec.reason_digest == PIN2
    assert rec.severity == 42
    assert rec.digest.startswith("sha256:") and len(rec.digest) == 71
    # second booking mints obv-2
    rec2 = _verdict(ledger, "obs-1", 2)
    assert rec2.verdict_id == "obv-2"
    # frozen
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.severity = 0  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec2.verdict = "allow"  # type: ignore[misc]


# 4. bad-input table -> all raise ObserverVerdictError
def test_verdict_bad_inputs():
    ledger = ovl.ObserverVerdictLedger()
    seq = 0

    def nxt():
        nonlocal seq
        seq += 1
        return seq

    # empty observer_id (raises before seq claim)
    with pytest.raises(ovl.ObserverVerdictError):
        ledger.verdict("", nxt(), PIN, "allow", PIN2)
    # bad action_digest pins
    for bad_pin in ("not-a-pin", "sha256:xyz", "sha256:" + "zz" * 32, "", 123):
        with pytest.raises(ovl.ObserverVerdictError):
            ledger.verdict("obs-bad", nxt(), bad_pin, "allow", PIN2)
    # bad verdict string
    with pytest.raises(ovl.ObserverVerdictError):
        ledger.verdict("obs-bad", nxt(), PIN, "maybe", PIN2)
    with pytest.raises(ovl.ObserverVerdictError):
        ledger.verdict("obs-bad", nxt(), PIN, "", PIN2)
    # bad reason_digest
    with pytest.raises(ovl.ObserverVerdictError):
        ledger.verdict("obs-bad", nxt(), PIN, "allow", "bad")
    # bad severity values
    for bad_sev in (-1, 101, True, False, "high", 1.5, None):
        with pytest.raises(ovl.ObserverVerdictError):
            ledger.verdict("obs-bad", nxt(), PIN, "allow", PIN2, severity=bad_sev)
    # bad observer_seq types burn seq + book rejected
    for bad_seq in ("1", 1.0, True, None):
        with pytest.raises(ovl.ObserverVerdictError):
            ledger.verdict("obs-bad", bad_seq, PIN, "allow", PIN2)


# 5. seq discipline: 1,2,3 ok; rewind bare; gap allowed
def test_seq_discipline():
    ledger = ovl.ObserverVerdictLedger()
    _verdict(ledger, "obs-S", 1)
    _verdict(ledger, "obs-S", 2)
    _verdict(ledger, "obs-S", 3)
    rejected_before = ledger.stats()["rejected"]
    audit_before = len(ledger.audit_log())
    # rewind raises bare: no rejected row, no audit row, seq not consumed
    with pytest.raises(ovl.ObserverVerdictError):
        _verdict(ledger, "obs-S", 2)
    assert ledger.stats()["rejected"] == rejected_before
    assert len(ledger.audit_log()) == audit_before
    # next valid seq still works (seq was NOT consumed by the rewind)
    rec = _verdict(ledger, "obs-S", 4)
    assert rec.observer_seq == 4
    # gap allowed: jump to 10, then 11 works
    rec10 = _verdict(ledger, "obs-S", 10)
    assert rec10.observer_seq == 10
    rec11 = _verdict(ledger, "obs-S", 11)
    assert rec11.observer_seq == 11


# 6. failed booking burns seq + books rejected row
def test_failed_booking_burns_seq():
    ledger = ovl.ObserverVerdictLedger()
    _verdict(ledger, "obs-F", 1)
    _verdict(ledger, "obs-F", 2)
    _verdict(ledger, "obs-F", 3)
    _verdict(ledger, "obs-F", 4)
    rejected_before = ledger.stats()["rejected"]
    with pytest.raises(ovl.ObserverVerdictError):
        ledger.verdict("obs-F", 5, PIN, "bogus-verdict", PIN2)
    assert ledger.stats()["rejected"] == rejected_before + 1
    # seq 5 was burned: reusing it is a rewind (bare raise, no new rejected)
    with pytest.raises(ovl.ObserverVerdictError):
        _verdict(ledger, "obs-F", 5)
    assert ledger.stats()["rejected"] == rejected_before + 1
    # next booking must use seq 6
    rec = _verdict(ledger, "obs-F", 6)
    assert rec.observer_seq == 6
    assert rec.verdict_id == "obv-5"  # 4 good + 1 good after burn


# 7. per-observer seq independence
def test_per_observer_seq_independence():
    ledger = ovl.ObserverVerdictLedger()
    a1 = _verdict(ledger, "obs-A", 1, verdict="allow")
    b1 = _verdict(ledger, "obs-B", 1, verdict="deny")
    assert a1.verdict_id == "obv-1"
    assert b1.verdict_id == "obv-2"
    a2 = _verdict(ledger, "obs-A", 2, verdict="flag")
    b2 = _verdict(ledger, "obs-B", 2, verdict="escalate")
    assert a2.observer_seq == 2
    assert b2.observer_seq == 2
    assert [r.verdict_id for r in ledger.verdicts_for("obs-A")] == ["obv-1", "obv-3"]
    assert [r.verdict_id for r in ledger.verdicts_for("obs-B")] == ["obv-2", "obv-4"]


# 8. retire: terminal, bad reason, double retire, post-retire verdict
def test_retire():
    ledger = ovl.ObserverVerdictLedger()
    _verdict(ledger, "obs-R", 1)
    rec = ledger.retire("obs-R", 2, reason="compromised")
    assert rec.observer_id == "obs-R"
    assert rec.seq == 2
    assert rec.reason == "compromised"
    assert rec.digest.startswith("sha256:")
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.reason = "manual"  # type: ignore[misc]
    # bad reason raises (before any state change)
    with pytest.raises(ovl.ObserverVerdictError):
        ledger.retire("obs-X", 1, reason="bogus")
    # double retire raises
    with pytest.raises(ovl.ObserverVerdictError):
        ledger.retire("obs-R", 3)
    # post-retire verdict raises + books rejected row
    rejected_before = ledger.stats()["rejected"]
    with pytest.raises(ovl.ObserverVerdictError):
        _verdict(ledger, "obs-R", 3)
    assert ledger.stats()["rejected"] == rejected_before + 1
    # retire with default reason
    r2 = ledger.retire("obs-R2", 1)
    assert r2.reason == "manual"


# 9. unknown lookups
def test_unknown_lookups():
    ledger = ovl.ObserverVerdictLedger()
    _verdict(ledger, "obs-U", 1)
    with pytest.raises(ovl.ObserverVerdictError):
        ledger.verdict_record("obv-999")
    with pytest.raises(ovl.ObserverVerdictError):
        ledger.to_sealed_event("obv-999")
    assert ledger.verdicts_for("no-such-observer") == ()


# 10. to_sealed_event: 8 keys, mappings, unknown id
def test_to_sealed_event():
    ledger = ovl.ObserverVerdictLedger()
    rec = _verdict(ledger, "obs-E", 7, verdict="escalate", severity=77)
    event = ledger.to_sealed_event(rec.verdict_id)
    assert set(event.keys()) == {
        "intent",
        "action",
        "subject",
        "authorization",
        "inputs_digest",
        "logic_digest",
        "execution_digest",
        "outcome",
    }
    assert len(event) == 8
    assert event["outcome"] == "escalate"
    assert event["inputs_digest"] == PIN
    assert event["logic_digest"] == PIN2
    assert event["execution_digest"] == rec.digest
    assert event["intent"] == "observer-verdict:escalate"
    assert event["action"] == "adjudicate"
    assert event["subject"] == "obs-E"
    assert event["authorization"] == "observer-seq:7"
    for key in ("inputs_digest", "logic_digest", "execution_digest"):
        assert event[key].startswith("sha256:") and len(event[key]) == 71
    with pytest.raises(ovl.ObserverVerdictError):
        ledger.to_sealed_event("obv-404")


# 11. stats shape after a scripted sequence
def test_stats():
    ledger = ovl.ObserverVerdictLedger()
    _verdict(ledger, "obs-A", 1, verdict="allow")
    _verdict(ledger, "obs-A", 2, verdict="deny")
    _verdict(ledger, "obs-B", 1, verdict="flag")
    with pytest.raises(ovl.ObserverVerdictError):
        ledger.verdict("obs-A", 3, PIN, "bogus", PIN2)  # rejected
    ledger.retire("obs-B", 2, reason="manual")  # retired
    stats = ledger.stats()
    assert stats["verdicts"] == 3
    assert stats["observers"] == 2
    assert stats["retired"] == 1
    assert stats["rejected"] == 1
    assert stats["audit_rows"] == 5  # 3 verdict + 1 rejected + 1 retired


# 12. audit_log kinds, schema, seqs
def test_audit_log():
    ledger = ovl.ObserverVerdictLedger()
    _verdict(ledger, "obs-A", 1, verdict="allow")
    _verdict(ledger, "obs-A", 2, verdict="deny")
    with pytest.raises(ovl.ObserverVerdictError):
        ledger.verdict("obs-A", 3, PIN, "bogus", PIN2)
    _verdict(ledger, "obs-A", 4, verdict="flag")
    ledger.retire("obs-A", 5)
    log = ledger.audit_log()
    assert [row["kind"] for row in log] == [
        "verdict", "verdict", "rejected", "verdict", "retired",
    ]
    for row in log:
        assert row["schema"] == "audit.ndjson/1"
        assert set(row.keys()) == {"kind", "seq", "ref", "schema"}
    assert [row["seq"] for row in log] == [1, 2, 3, 4, 5]
    assert log[0]["ref"] == "obv-1"
    assert log[2]["ref"] == "obs-A"  # rejected rows ref the observer
    assert log[4]["ref"] == "obs-A"  # retired rows ref the observer


# 13. full verdict vocabulary sweep
def test_full_verdict_vocabulary():
    ledger = ovl.ObserverVerdictLedger()
    for i, verdict in enumerate(ovl.VERDICTS, start=1):
        rec = _verdict(ledger, "obs-V", i, verdict=verdict)
        assert rec.verdict == verdict
        assert rec.verdict_id == f"obv-{i}"
    assert ledger.stats()["verdicts"] == 5


# 14. thread smoke: 4 threads x 25 verdicts on 2 observers
def test_thread_smoke():
    ledger = ovl.ObserverVerdictLedger()
    counters = {"obs-T0": 0, "obs-T1": 0}
    counter_lock = threading.Lock()
    errors = []

    def worker(tid):
        obs = f"obs-T{tid // 2}"
        try:
            for _ in range(25):
                with counter_lock:
                    counters[obs] += 1
                    seq = counters[obs]
                    # draw + book atomically per observer: seqs stay increasing
                    ledger.verdict(obs, seq, PIN, "allow", PIN2)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    stats = ledger.stats()
    assert stats["verdicts"] == 100
    assert stats["observers"] == 2
    for obs in ("obs-T0", "obs-T1"):
        recs = ledger.verdicts_for(obs)
        assert len(recs) == 50
        seqs = sorted(r.observer_seq for r in recs)
        assert seqs == list(range(1, 51))
        assert len({r.verdict_id for r in recs}) == 50


# 15. main() subprocess check
def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "OK" in proc.stdout
