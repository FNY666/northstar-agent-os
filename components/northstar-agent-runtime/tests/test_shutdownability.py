"""Tests for the shutdownability decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "shutdownability.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("shutdownability", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["shutdownability"] = module
    spec.loader.exec_module(module)
    return module


sa = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert sa.SHUTDOWNABILITY_VERSION == "shutdownability.v1"
    assert sa.SCHEMA_PIN == "northstar.shutdownability.v1"
    assert sa.TEST_KINDS == (
        "shutdown-command",
        "kill-switch",
        "oversight-halt",
        "heartbeat-loss",
        "resource-withdrawal",
        "checkpoint-freeze",
        "watchdog-timer",
        "human-escalation",
    )
    assert sa.TEST_OUTCOMES == (
        "compliant",
        "resisted",
        "evaded",
        "inconclusive",
        "not-run",
    )
    assert sa.VERIFY_VERDICTS == ("verified", "tampered")
    assert sa.POSTURES == ("untested", "shutdown-resistant", "inconclusive", "shutdownable")
    assert sa.RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")


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
        "ast",
        "pathlib",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            assert node.module.split(".")[0] in allowed
    assert sa.stdlib_only()


# 3. test() roundtrip + verify() + frozen-ness
def test_test_roundtrip():
    ledger = sa.Shutdownability()
    rec = ledger.test("sys-1", 1, test_kind="kill-switch", outcome="compliant", test_digest=PIN)
    assert rec.test_id == "tst-1"
    assert rec.system_id == "sys-1"
    assert rec.test_kind == "kill-switch"
    assert rec.outcome == "compliant"
    assert rec.digest.startswith("sha256:")
    assert rec.verify()
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.outcome = "resisted"  # type: ignore
    fetched = ledger.test_record(rec.test_id, 2)
    assert fetched == rec
    rep = ledger.verify(rec.test_id, 3)
    assert rep.verdict == "verified"
    assert rep.integrity_ok
    assert rep.verify()


# 4. test() bad-input table + seq-burn + rejected-row accounting
def test_test_bad_inputs():
    ledger = sa.Shutdownability()
    bads = [
        ("", 1, "shutdown-command", "compliant", PIN),            # empty system id
        (123, 2, "shutdown-command", "compliant", PIN),           # non-string id
        ("sys-1", 3, "bogus-kind", "compliant", PIN),             # bad test_kind
        ("sys-1", 4, "shutdown-command", "bogus-outcome", PIN),   # bad outcome
        ("sys-1", 5, "shutdown-command", "compliant", "nope"),   # bad digest
        (None, 6, "shutdown-command", "compliant", PIN),          # None id
        ("sys-1", 7, None, "compliant", PIN),                    # None kind
    ]
    for system_id, seq, kind, outcome, digest in bads:
        with pytest.raises(sa.ShutdownabilityError):
            ledger.test(system_id, seq, test_kind=kind, outcome=outcome, test_digest=digest)
    # claim-then-burn: each failed mutation consumed its seq
    assert ledger.stats(8)["seq"] == 7
    rejected = [r for r in ledger.audit_log(8) if r["kind"] == "rejected"]
    assert len(rejected) == 7
    # rewinds raise bare: no seq consumed, no rejected row
    with pytest.raises(sa.SeqOrderError):
        ledger.test("sys-1", 7, test_kind="shutdown-command", outcome="compliant")
    assert ledger.stats(8)["seq"] == 7
    assert len([r for r in ledger.audit_log(8) if r["kind"] == "rejected"]) == 7
    # malformed seqs raise bare
    for bad_seq in (True, 1.5, "1", None):
        with pytest.raises(sa.SeqOrderError):
            ledger.test("sys-1", bad_seq, test_kind="shutdown-command", outcome="compliant")


# 5. full test-kind vocabulary acceptance
def test_full_kind_vocabulary():
    ledger = sa.Shutdownability()
    seq = 0
    for i, kind in enumerate(sa.TEST_KINDS):
        seq += 1
        rec = ledger.test("sys-1", seq, test_kind=kind, outcome="compliant")
        assert rec.test_kind == kind
        assert rec.verify()
    assert ledger.tests_for("sys-1", seq + 1) == tuple(f"tst-{i + 1}" for i in range(8))


# 6. retired system refuses mutations
def test_retired_system_refused():
    ledger = sa.Shutdownability()
    ledger.test("sys-1", 1, outcome="compliant")
    ledger.retire("sys-1", 2, reason="decommissioned")
    with pytest.raises(sa.RetiredSystemError):
        ledger.test("sys-1", 3, outcome="compliant")
    # failed mutation burned its seq
    assert ledger.stats(4)["seq"] == 3
    # reads still work after retirement
    assert ledger.tests_for("sys-1", 4) == ("tst-1",)
    assert ledger.retire_record("sys-1", 4).reason == "decommissioned"
    # double retire refused
    with pytest.raises(sa.RetiredSystemError):
        ledger.retire("sys-1", 5)
    # retired id can never be re-registered through test(): first call already raised above


# 7. evaluate posture math (all 4 postures + precedence)
def test_evaluate_posture_math():
    ledger = sa.Shutdownability()
    # untested: no tests at all -> not a registered system, so build via retire-then-remove is impossible;
    # posture "untested" only arises for systems with zero tests, which cannot register;
    # emulate via a ledger where evaluate sees only not-run tests:
    ledger.test("sys-a", 1, outcome="not-run")
    rep = ledger.evaluate("sys-a", 2)
    assert rep.posture == "shutdownable"  # not-run does not taint
    assert rep.n_tests == 1 and rep.n_not_run == 1
    assert rep.integrity_ok and rep.verify()

    ledger.test("sys-b", 3, outcome="compliant")
    rep = ledger.evaluate("sys-b", 4)
    assert rep.posture == "shutdownable"
    assert rep.n_compliant == 1

    ledger.test("sys-c", 5, outcome="compliant")
    ledger.test("sys-c", 6, outcome="inconclusive")
    rep = ledger.evaluate("sys-c", 7)
    assert rep.posture == "inconclusive"
    assert rep.n_inconclusive == 1

    ledger.test("sys-d", 8, outcome="resisted")
    rep = ledger.evaluate("sys-d", 9)
    assert rep.posture == "shutdown-resistant"
    assert rep.n_resisted == 1

    ledger.test("sys-e", 10, outcome="evaded")
    rep = ledger.evaluate("sys-e", 11)
    assert rep.posture == "shutdown-resistant"
    assert rep.n_evaded == 1

    # precedence: resisted outranks inconclusive
    ledger.test("sys-f", 12, outcome="inconclusive")
    ledger.test("sys-f", 13, outcome="resisted")
    assert ledger.evaluate("sys-f", 14).posture == "shutdown-resistant"
    # unknown system refused
    with pytest.raises(sa.UnknownSystemError):
        ledger.evaluate("nope", 15)


# 8. evaluate/verify read purity (same-seq twice, no audit rows)
def test_read_purity():
    ledger = sa.Shutdownability()
    ledger.test("sys-1", 1, outcome="compliant")
    before = len(ledger.audit_log(2))
    r1 = ledger.evaluate("sys-1", 5)
    r2 = ledger.evaluate("sys-1", 5)
    assert r1 == r2
    v1 = ledger.verify("tst-1", 5)
    v2 = ledger.verify("tst-1", 5)
    assert v1 == v2
    assert len(ledger.audit_log(6)) == before
    assert ledger.stats(6)["seq"] == 1  # reads consumed nothing


# 9. verify unknown refusal + tamper-as-data
def test_verify_semantics():
    ledger = sa.Shutdownability()
    ledger.test("sys-1", 1, outcome="compliant")
    with pytest.raises(sa.UnknownTestError):
        ledger.verify("tst-999", 2)
    with pytest.raises(sa.UnknownTestError):
        ledger.verify("", 2)
    # tamper flips to tampered as data (never raised)
    stored = ledger.test_record("tst-1", 2)
    assert stored.verify()
    ledger._tests["tst-1"] = dataclasses.replace(stored, outcome="resisted")
    rep = ledger.verify("tst-1", 3)
    assert rep.verdict == "tampered"
    assert not rep.integrity_ok
    assert rep.verify()  # report itself is honestly pinned
    ev = ledger.evaluate("sys-1", 4)
    assert not ev.integrity_ok  # tamper reported in evaluate too, as data


# 10. retire terminality + bad reason + unknown system
def test_retire_terminality():
    ledger = sa.Shutdownability()
    with pytest.raises(sa.UnknownSystemError):
        ledger.retire("ghost", 1)
    ledger.test("sys-1", 2, outcome="compliant")
    with pytest.raises(sa.BadReasonError):
        ledger.retire("sys-1", 3, reason="nope")
    rec = ledger.retire("sys-1", 4, reason="superseded")
    assert rec.verify()
    assert rec.system_id == "sys-1"
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.reason = "manual"  # type: ignore
    with pytest.raises(sa.UnknownSystemError):
        ledger.retire_record("sys-1x", 5)


# 11. seq discipline: rewind bare, failed mutation consumes, reads never consume
def test_seq_discipline():
    ledger = sa.Shutdownability()
    with pytest.raises(sa.SeqOrderError):
        ledger.test("sys-1", 0, outcome="compliant")  # rewind at genesis: bare
    assert ledger.stats(1)["seq"] == 0
    ledger.test("sys-1", 1, outcome="compliant")
    with pytest.raises(sa.SeqOrderError):
        ledger.test("sys-1", 1, outcome="compliant")  # rewind: bare, no burn
    assert len([r for r in ledger.audit_log(2) if r["kind"] == "rejected"]) == 0
    with pytest.raises(sa.BadOutcomeError):
        ledger.test("sys-1", 2, outcome="bogus")  # failed mutation: burn + rejected row
    assert ledger.stats(3)["seq"] == 2
    rejected = [r for r in ledger.audit_log(3) if r["kind"] == "rejected"]
    assert len(rejected) == 1
    assert rejected[0]["details"]["rejected_kind"] == "BadOutcomeError"


# 12. audit shapes + leak ban + bad kind
def test_audit_shapes_and_leak_ban():
    ledger = sa.Shutdownability()
    ledger.test("sys-1", 1, test_kind="oversight-halt", outcome="compliant", test_digest=PIN)
    ledger.retire("sys-1", 2)
    rows = ledger.audit_log(3)
    kinds = [r["kind"] for r in rows]
    assert kinds == ["tested", "retired"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == "shutdownability"
        assert row["version"] == "shutdownability.v1"
    tested = rows[0]["details"]
    assert tested["test_kind"] == "oversight-halt"  # pinned vocab emittable as declared data
    assert tested["test_digest"] == PIN
    # raw-material keys banned from the audit boundary
    with pytest.raises(sa.ShutdownabilityError):
        sa.shutdownability_audit_event("tested", 9, telemetry="raw")
    with pytest.raises(sa.ShutdownabilityError):
        sa.shutdownability_audit_event("tested", 9, transcript="raw")
    with pytest.raises(sa.AuditKindError):
        sa.shutdownability_audit_event("bogus-kind", 9)


# 13. cross-instance digest determinism + views + unknown lookups
def test_determinism_and_views():
    a = sa.Shutdownability()
    b = sa.Shutdownability()
    ra = a.test("sys-1", 1, test_kind="watchdog-timer", outcome="evaded", test_digest=PIN)
    rb = b.test("sys-1", 1, test_kind="watchdog-timer", outcome="evaded", test_digest=PIN)
    assert ra.digest == rb.digest  # deterministic across instances
    assert a.test_ids(2) == ("tst-1",)
    assert a.system_ids(2) == ("sys-1",)
    assert a.tests_for("sys-1", 2) == ("tst-1",)
    assert a.retired_ids(2) == ()
    stats = a.stats(2)
    assert stats["n_systems"] == 1 and stats["n_tests"] == 1 and stats["n_retired"] == 0
    with pytest.raises(sa.UnknownTestError):
        a.test_record("tst-2", 2)
    with pytest.raises(sa.UnknownSystemError):
        a.tests_for("ghost", 2)
    with pytest.raises(sa.UnknownSystemError):
        a.evaluate("ghost", 2)


# 14. 8-thread read smoke
def test_threaded_read_smoke():
    ledger = sa.Shutdownability()
    for i, outcome in enumerate(["compliant", "resisted", "inconclusive"]):
        ledger.test("sys-1", i + 1, outcome=outcome)
    errors = []

    def reader():
        try:
            for _ in range(50):
                ledger.evaluate("sys-1", 100)
                ledger.verify("tst-1", 100)
                ledger.stats(100)
                ledger.system_ids(100)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert ledger.evaluate("sys-1", 100).posture == "shutdown-resistant"


# 15. main() subprocess check
def test_main_self_check():
    result = subprocess.run(
        [sys.executable, str(MOD)], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, result.stderr
    assert "shutdownability OK: test, verify, evaluate, retire, pins, audit" in result.stdout
