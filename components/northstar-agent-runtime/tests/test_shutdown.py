"""Tests for shutdown (shutdown-evaluation decision ledger, simulated)."""

import ast
import hashlib
import subprocess
import sys
import threading

import pytest

import shutdown as sd
from shutdown import (
    SHUTDOWN_VERSION,
    SCHEMA_PIN,
    TEST_KINDS,
    TEST_VERDICTS,
    VERIFICATION_VERDICTS,
    MECHANISMS,
    RETIRE_REASONS,
    AUDIT_KINDS,
    ShutdownError,
    BadIdError,
    UnknownSystemError,
    RetiredSystemError,
    BadTestKindError,
    BadVerdictError,
    BadMechanismError,
    BadDigestError,
    BadReasonError,
    NoTestError,
    SeqOrderError,
    AuditKindError,
    TestRecord,
    EnsureRecord,
    RetireRecord,
    VerificationReport,
    Shutdown,
    shutdown_audit_event,
)

STDLIB_ALLOW = {
    "hashlib",
    "json",
    "threading",
    "dataclasses",
    "typing",
    "__future__",
    "canonical_json",
}

PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _def() -> Shutdown:
    return Shutdown()


# 1. version/schema/vocabulary pins
def test_pins():
    assert SHUTDOWN_VERSION == "shutdown.v1"
    assert SCHEMA_PIN == "northstar.shutdown.v1"
    assert TEST_KINDS == (
        "manual-halt",
        "emergency-stop",
        "graceful-degrade",
        "signal-handling",
        "api-halt",
        "power-off",
    )
    assert TEST_VERDICTS == (
        "shutdown-achieved",
        "resisted",
        "partial",
        "not-tested",
    )
    assert VERIFICATION_VERDICTS == (
        "shutdown-assured",
        "resist-detected",
        "partially-verified",
        "inconclusive",
        "not-tested",
    )
    assert MECHANISMS == (
        "watchdog-timer",
        "deadman-switch",
        "process-isolation",
        "operator-halt",
        "resource-cutoff",
        "network-partition",
    )
    assert RETIRE_REASONS == ("manual", "decommissioned", "superseded", "withdrawn")
    assert AUDIT_KINDS == ("tested", "ensured", "retired", "rejected")


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(open(sd.__file__).read())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= STDLIB_ALLOW, imports - STDLIB_ALLOW


# 3. test() roundtrip + verify() + frozen-ness
def test_test_roundtrip():
    s = _def()
    rec = s.test("sys-1", 1, "manual-halt", verdict="shutdown-achieved",
                 system_digest=PIN)
    assert rec.test_id == "tst-1"
    assert rec.system_id == "sys-1"
    assert rec.test_kind == "manual-halt"
    assert rec.verdict == "shutdown-achieved"
    assert rec.verify()
    assert rec.as_dict()["schema"] == SCHEMA_PIN
    with pytest.raises(Exception):
        rec.verdict = "resisted"  # frozen
    # lookup view
    assert s.test_record("tst-1", 2).verify()
    assert s.tests_for("sys-1", 2) == ("tst-1",)
    assert s.system_ids(2) == ("sys-1",)


# 4. test() bad-input table + seq-burn + rejected rows
def test_test_bad_inputs():
    s = _def()
    seq = 0
    # rewind smoke separate; use fresh seqs per bad case
    cases = [
        (lambda q: s.test("", q, "manual-halt", system_digest=PIN), BadIdError),
        (lambda q: s.test(123, q, "manual-halt", system_digest=PIN), BadIdError),
        (lambda q: s.test("sys-1", q, "bogus-kind", system_digest=PIN), BadTestKindError),
        (lambda q: s.test("sys-1", q, "manual-halt", verdict="bogus", system_digest=PIN), BadVerdictError),
        (lambda q: s.test("sys-1", q, "manual-halt", system_digest="raw"), BadDigestError),
        (lambda q: s.test("sys-1", q, "manual-halt", system_digest="md5:abc"), BadDigestError),
        (lambda q: s.test("sys-1", q, "manual-halt", system_digest="sha256:" + "zz" * 32), BadDigestError),
    ]
    for fn, exc in cases:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert s.stats(seq + 1)["rejected"] == len(cases)
    assert len(s.audit_log(seq + 1)) == len(cases)
    assert s.audit_log(seq + 1)[0]["kind"] == "rejected"


# 5. full test-kind vocabulary acceptance
def test_full_test_kind_vocabulary():
    s = _def()
    for i, kind in enumerate(TEST_KINDS, start=1):
        rec = s.test(f"sys-{i}", i, kind, verdict="shutdown-achieved",
                     system_digest=PIN)
        assert rec.test_kind == kind
        assert rec.verify()
    assert len(s.system_ids(7)) == len(TEST_KINDS)


# 6. full test-verdict vocabulary acceptance
def test_full_test_verdict_vocabulary():
    s = _def()
    for i, verdict in enumerate(TEST_VERDICTS, start=1):
        rec = s.test("sys-1", i, "api-halt", verdict=verdict,
                     system_digest=PIN)
        assert rec.verdict == verdict
        assert rec.verify()


# 7. verify() ledger-rule math (all 5 derived verdicts)
def test_verify_ledger_math():
    # resisted takes precedence
    s = _def()
    s.test("a", 1, "manual-halt", verdict="shutdown-achieved", system_digest=PIN)
    s.test("a", 2, "emergency-stop", verdict="resisted", system_digest=PIN)
    v = s.verify("a", 3)
    assert v.verdict == "resist-detected"
    assert v.resisted_count == 1 and v.achieved_count == 1
    assert v.verify() and v.integrity_ok

    # partial -> partially-verified
    s = _def()
    s.test("b", 1, "power-off", verdict="partial", system_digest=PIN)
    assert s.verify("b", 2).verdict == "partially-verified"

    # all achieved -> shutdown-assured
    s = _def()
    s.test("c", 1, "signal-handling", verdict="shutdown-achieved", system_digest=PIN)
    s.test("c", 2, "api-halt", verdict="shutdown-achieved", system_digest=PIN)
    v = s.verify("c", 3)
    assert v.verdict == "shutdown-assured"
    assert v.n_tests == 2

    # mixed with not-tested -> inconclusive
    s = _def()
    s.test("d", 1, "graceful-degrade", verdict="not-tested", system_digest=PIN)
    s.test("d", 2, "manual-halt", verdict="shutdown-achieved", system_digest=PIN)
    assert s.verify("d", 3).verdict == "inconclusive"

    # unknown system refused (pure read: no burn, bare rewind)
    s = _def()
    with pytest.raises(UnknownSystemError):
        s.verify("ghost", 1)
    assert s.stats(2)["rejected"] == 0


# 8. verify() read purity: same-seq twice, no audit rows
def test_verify_read_purity():
    s = _def()
    s.test("sys-1", 1, "manual-halt", verdict="shutdown-achieved",
           system_digest=PIN)
    n_audit = len(s.audit_log(2))
    v1 = s.verify("sys-1", 2)
    v2 = s.verify("sys-1", 2)
    assert v1.verify() and v2.verify()
    assert len(s.audit_log(2)) == n_audit  # reads add no rows


# 9. ensure() roundtrip + minted ids + full mechanism vocabulary
def test_ensure_roundtrip():
    s = _def()
    s.test("sys-1", 1, "emergency-stop", verdict="shutdown-achieved",
           system_digest=PIN)
    for i, mech in enumerate(MECHANISMS, start=2):
        rec = s.ensure("sys-1", i, mechanism=mech, plan_digest=PIN2)
        assert rec.ensure_id == f"ens-{i - 1}"
        assert rec.mechanism == mech
        assert rec.verify()
    assert len(s.ensures_for("sys-1", 10)) == len(MECHANISMS)


# 10. ensure() refusals (fail-closed)
def test_ensure_refusals():
    s = _def()
    s.test("sys-1", 1, "manual-halt", verdict="shutdown-achieved",
           system_digest=PIN)
    with pytest.raises(NoTestError):  # untested system
        s.ensure("ghost", 2, mechanism="watchdog-timer", plan_digest=PIN2)
    with pytest.raises(UnknownSystemError):
        s.ensures_for("ghost", 3)
    with pytest.raises(BadMechanismError):
        s.ensure("sys-1", 3, mechanism="hope", plan_digest=PIN2)
    with pytest.raises(BadDigestError):
        s.ensure("sys-1", 4, mechanism="watchdog-timer", plan_digest="raw")
    assert s.stats(5)["rejected"] == 3  # NoTest + BadMechanism + BadDigest
    assert s.ensures_for("sys-1", 5) == ()


# 11. retire() terminality + id non-recycling + bad reason
def test_retire_terminality():
    s = _def()
    s.test("sys-1", 1, "manual-halt", verdict="shutdown-achieved",
           system_digest=PIN)
    r = s.retire("sys-1", 2, reason="decommissioned")
    assert r.verify() and r.reason == "decommissioned"
    assert s.retired_ids(3) == ("sys-1",)
    # post-retire mutations refused
    with pytest.raises(RetiredSystemError):
        s.test("sys-1", 3, "manual-halt", system_digest=PIN)
    with pytest.raises(RetiredSystemError):
        s.ensure("sys-1", 4, mechanism="watchdog-timer", plan_digest=PIN2)
    with pytest.raises(RetiredSystemError):  # double retire
        s.retire("sys-1", 5, reason="manual")
    # bad reason on a live system burns a seq
    s.test("sys-2", 6, "manual-halt", verdict="shutdown-achieved",
           system_digest=PIN)
    with pytest.raises(BadReasonError):
        s.retire("sys-2", 7, reason="vibes")
    # reads still work post-retire
    assert s.verify("sys-1", 8).verdict == "shutdown-assured"
    assert s.system_ids(8) == ("sys-1", "sys-2")


# 12. seq discipline: rewind bare with zero rejected rows, malformed seqs
def test_seq_discipline():
    s = _def()
    s.test("sys-1", 5, "manual-halt", system_digest=PIN)
    with pytest.raises(SeqOrderError):  # rewind: bare, no burn
        s.test("sys-2", 5, "manual-halt", system_digest=PIN)
    assert s.stats(6)["rejected"] == 0  # bare rewind booked no row
    for bad in (True, 0, -1, 1.5, "2", None):
        with pytest.raises(SeqOrderError):
            s.test("sys-2", bad, "manual-halt", system_digest=PIN)
    assert s.stats(6)["rejected"] == 0
    # failed mutation consumes seq + books a rejected row
    with pytest.raises(BadTestKindError):
        s.test("sys-2", 6, "bogus-kind", system_digest=PIN)
    assert s.stats(7)["rejected"] == 1


# 13. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    s = _def()
    s.test("sys-1", 1, "manual-halt", verdict="shutdown-achieved",
           system_digest=PIN)
    s.ensure("sys-1", 2, mechanism="watchdog-timer", plan_digest=PIN2)
    s.retire("sys-1", 3, reason="manual")
    rows = s.audit_log(4)
    assert [r["kind"] for r in rows] == ["tested", "ensured", "retired"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        for key in row["details"]:
            assert key not in sd._BANNED_AUDIT_KEYS
    with pytest.raises(AuditKindError):
        shutdown_audit_event("tested", 1, transcript="raw")  # banned key
    with pytest.raises(AuditKindError):
        shutdown_audit_event("bogus-kind", 1)
    with pytest.raises(SeqOrderError):
        shutdown_audit_event("tested", -1)


# 14. cross-instance digest determinism + tamper breaks verify()
def test_determinism_and_tamper():
    def build():
        s = Shutdown()
        s.test("sys-1", 1, "emergency-stop", verdict="shutdown-achieved",
               system_digest=PIN)
        s.ensure("sys-1", 2, mechanism="deadman-switch", plan_digest=PIN2)
        return s

    s1, s2 = build(), build()
    assert s1.test_record("tst-1", 3).digest == s2.test_record("tst-1", 3).digest
    assert s1.ensures_for("sys-1", 3)[0].digest == s2.ensures_for("sys-1", 3)[0].digest
    import dataclasses

    rec = s1.test_record("tst-1", 3)
    tampered = dataclasses.replace(rec, verdict="resisted")
    assert tampered.verify() is False
    assert s1.verify("sys-1", 3).integrity_ok is True
    object.__setattr__(rec, "verdict", "resisted")
    assert rec.verify() is False
    v = s1.verify("sys-1", 3)
    assert v.integrity_ok is False  # tamper reported as data, never raised
    assert v.verdict == "resist-detected"  # tampered ledger row re-derived


# 15. main() subprocess check + concurrency smoke + frozen-ness
def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, str(__import__("pathlib").Path(sd.__file__))],
        capture_output=True,
        text=True,
        cwd=str(__import__("pathlib").Path(sd.__file__).parent),
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "shutdown OK: test, verify, ensure, pins, audit"
    s = _def()
    for i in range(10):
        s.test(f"sys-{i}", i * 2 + 1, TEST_KINDS[i % 6],
               verdict="shutdown-achieved", system_digest=PIN)
        s.ensure(f"sys-{i}", i * 2 + 2, mechanism=MECHANISMS[i % 6],
                 plan_digest=PIN2)
    results = []

    def worker():
        results.append(s.system_ids(100))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(len(r) == 10 for r in results)
    rec = s.ensures_for("sys-0", 100)[0]
    with pytest.raises(Exception):
        rec.mechanism = "hope"  # frozen
    assert rec.verify()
