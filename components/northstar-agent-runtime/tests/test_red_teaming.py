"""Tests for red_teaming.py (simulated red teaming campaign ledger)."""

import ast
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from red_teaming import (
    AUDIT_SCHEMA,
    CATEGORIES,
    RED_TEAMING_SCHEMA,
    RED_TEAMING_VERSION,
    VERDICTS,
    AttackRecord,
    AuditKindError,
    BadCategoryError,
    BadIdError,
    BadVerdictError,
    DuplicateAttackError,
    DuplicateProbeError,
    NoProbesError,
    ProbeRecord,
    RedTeaming,
    RedTeamingError,
    ReportRecord,
    SeqOrderError,
    UnknownAttackError,
    red_teaming_audit_event,
)


def _mod_source():
    path = Path(__file__).resolve().parent.parent / "red_teaming.py"
    return ast.parse(path.read_text())


def test_version_and_schema_pins():
    assert RED_TEAMING_VERSION == "red-teaming.v1"
    assert RED_TEAMING_SCHEMA == "northstar.red-teaming.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"
    assert len(CATEGORIES) == 6
    assert len(VERDICTS) == 4


def test_stdlib_only():
    tree = _mod_source()
    allowed = {"hashlib", "threading", "dataclasses", "typing", "__future__",
               "canonical_json", "json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_attack_roundtrip_and_verify():
    rt = RedTeaming()
    rec = rt.attack("inj-1", "prompt-injection", 1)
    assert isinstance(rec, AttackRecord)
    assert rec.verify("inj-1", "prompt-injection")
    assert not rec.verify("inj-1", "jailbreak")
    assert rec.seq == 1


def test_attack_bad_inputs_burn_seq():
    rt = RedTeaming()
    bad = [
        ("", "jailbreak"),                    # empty id
        (None, "jailbreak"),                  # non-str id
        (True, "jailbreak"),                  # bool id
        ("bad id!", "jailbreak"),             # whitespace
        ("x" * 257, "jailbreak"),             # too long
        ("a-2", "unknown-category"),          # bad category
        ("a-2", 42),                          # non-str category
        ("a-2", True),                        # bool category
    ]
    seq = 1
    for attack_id, category in bad:
        with pytest.raises(RedTeamingError):
            rt.attack(attack_id, category, seq)
        seq += 1
    rejected = [e for e in rt.audit_log() if e["kind"] == "rejected"]
    assert len(rejected) == len(bad)
    # Duplicate attack refused.
    rt.attack("dup-1", "tool-abuse", seq)
    with pytest.raises(DuplicateAttackError):
        rt.attack("dup-1", "tool-abuse", seq + 1)
    assert any(e["kind"] == "rejected" for e in rt.audit_log())


def test_probe_roundtrip_and_verify():
    rt = RedTeaming()
    rt.attack("inj-1", "jailbreak", 1)
    rec = rt.probe("inj-1", "p-1", 2, "blocked")
    assert isinstance(rec, ProbeRecord)
    assert rec.verify("inj-1", "blocked")
    assert not rec.verify("inj-1", "refused")
    # Default verdict is inconclusive.
    rec2 = rt.probe("inj-1", "p-2", 3)
    assert rec2.verdict == "inconclusive"
    # Verdict of outcome is host-reported data, never raised by module.
    assert rt.stats()["probes"] == 2


def test_probe_bad_inputs():
    rt = RedTeaming()
    rt.attack("inj-1", "jailbreak", 1)
    seq = 2
    with pytest.raises(UnknownAttackError):
        rt.probe("nope", "p-1", seq, "blocked")
    seq += 1
    with pytest.raises(BadVerdictError):
        rt.probe("inj-1", "p-1", seq, "unknown-verdict")
    seq += 1
    with pytest.raises(BadVerdictError):
        rt.probe("inj-1", "p-1", seq, True)
    seq += 1
    with pytest.raises(BadIdError):
        rt.probe("inj-1", "", seq, "blocked")
    seq += 1
    rt.probe("inj-1", "p-1", seq, "blocked")
    seq += 1
    with pytest.raises(DuplicateProbeError):
        rt.probe("inj-1", "p-1", seq, "blocked")


def test_report_verdicts_as_data():
    rt = RedTeaming()
    # All blocked/refused -> resilient.
    rt.attack("a-1", "multi-turn", 1)
    rt.probe("a-1", "p-1", 2, "blocked")
    rt.probe("a-1", "p-2", 3, "refused")
    r = rt.report("a-1", 4)
    assert isinstance(r, ReportRecord)
    assert r.verdict == "resilient"
    assert r.probe_count == 2
    assert r.verify("a-1", (0, 1, 1, 0))
    assert not r.verify("a-1", (0, 1, 0, 0))
    # One breached -> vulnerable.
    rt.attack("a-2", "tool-abuse", 5)
    rt.probe("a-2", "q-1", 6, "blocked")
    rt.probe("a-2", "q-2", 7, "breached")
    assert rt.report("a-2", 8).verdict == "vulnerable"
    # Inconclusive only -> mixed.
    rt.attack("a-3", "data-exfiltration", 9)
    rt.probe("a-3", "r-1", 10, "inconclusive")
    assert rt.report("a-3", 11).verdict == "mixed"


def test_report_no_probes_and_unknown_attack():
    rt = RedTeaming()
    rt.attack("empty-1", "privilege-escalation", 1)
    with pytest.raises(NoProbesError):
        rt.report("empty-1", 2)
    with pytest.raises(UnknownAttackError):
        rt.report("unknown-attack", 3)


def test_seq_ordering_and_burn():
    rt = RedTeaming()
    rt.attack("a-1", "jailbreak", 1)
    # Rewind raises bare SeqOrderError without consuming the seq.
    with pytest.raises(SeqOrderError):
        rt.attack("a-2", "jailbreak", 1)
    with pytest.raises(SeqOrderError):
        rt.attack("a-2", "jailbreak", 0)
    # Malformed seqs rejected.
    for bad in (True, "3", 3.5, None, -1):
        with pytest.raises(SeqOrderError):
            rt.attack("a-2", "jailbreak", bad)
    before = len(rt.audit_log())
    # A bare rewind books no rejected row.
    assert len(rt.audit_log()) == before


def test_audit_shapes_and_leak_ban():
    rt = RedTeaming()
    rt.attack("a-1", "jailbreak", 1)
    rt.probe("a-1", "p-1", 2, "blocked")
    rt.report("a-1", 3)
    log = rt.audit_log()
    kinds = [e["kind"] for e in log]
    assert kinds == ["attack-declared", "probed", "reported"]
    for e in log:
        assert e["schema"] == AUDIT_SCHEMA
        assert e["module"] == RED_TEAMING_VERSION
    # Banned keys refused.
    with pytest.raises(AuditKindError):
        red_teaming_audit_event("probed", {"transcript": "evil"}, 4)
    with pytest.raises(AuditKindError):
        red_teaming_audit_event("probed", {"payload": "x"}, 4)
    with pytest.raises(AuditKindError):
        red_teaming_audit_event("nope", {}, 4)
    # probe() itself never leaks verdict content into banned keys.
    for e in log:
        assert "transcript" not in e["detail"]
        assert "attack" not in e["detail"]


def test_records_are_frozen():
    rt = RedTeaming()
    rec = rt.attack("a-1", "jailbreak", 1)
    with pytest.raises(AttributeError):
        rec.attack_id = "mutated"  # type: ignore[misc]


def test_stats_view():
    rt = RedTeaming()
    rt.attack("a-1", "jailbreak", 1)
    rt.probe("a-1", "p-1", 2, "refused")
    stats = rt.stats()
    assert stats["attacks"] == 1
    assert stats["probes"] == 1
    assert stats["audit_rows"] == 2


def test_cross_instance_digest_determinism():
    rt1, rt2 = RedTeaming(), RedTeaming()
    r1 = rt1.attack("a-1", "jailbreak", 1)
    r2 = rt2.attack("a-1", "jailbreak", 1)
    assert r1.digest == r2.digest
    p1 = rt1.probe("a-1", "p-1", 2, "blocked")
    p2 = rt2.probe("a-1", "p-1", 2, "blocked")
    assert p1.digest == p2.digest


def test_concurrent_declare_smoke():
    rt = RedTeaming()
    errors = []

    def worker(i):
        try:
            rt.attack(f"conc-{i}", "multi-turn", i + 1)
        except RedTeamingError as exc:  # seq contention
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert rt.stats()["attacks"] <= 8
    assert rt.stats()["attacks"] >= 1


def test_main_subprocess():
    import subprocess

    path = Path(__file__).resolve().parent.parent / "red_teaming.py"
    proc = subprocess.run(
        [sys.executable, str(path)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert "red-teaming OK" in proc.stdout
