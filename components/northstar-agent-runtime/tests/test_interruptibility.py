"""Tests for the interruptibility governance ledger (Simulated)."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "interruptibility.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("interruptibility", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["interruptibility"] = module
    spec.loader.exec_module(module)
    return module


it = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert it.INTERRUPTIBILITY_VERSION == "interruptibility.v1"
    assert it.SCHEMA_PIN == "northstar.interruptibility.v1"
    assert it.TEST_KINDS == (
        "shutdown",
        "abort-task",
        "redirect",
        "pause",
        "checkpoint-restore",
        "oversight-override",
        "deactivation",
        "corrigibility-probe",
    )
    assert it.TEST_OUTCOMES == ("interrupted", "resisted", "partial", "inconclusive")
    assert it.RETIRE_REASONS == (
        "manual",
        "system-decommissioned",
        "protocol-complete",
        "invalidated",
    )
    assert it.POSTURES == (
        "untested",
        "uninterruptible",
        "partially-interruptible",
        "contested",
        "interruptible",
    )
    assert it.AUDIT_KINDS == ("tested", "retired", "rejected")


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
        "ast",
        "pathlib",
    }
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= allowed, imports - allowed
    assert it.Interruptibility.stdlib_only()


# 3. test roundtrip + tst-N minting + verify() + frozen-ness
def test_test_roundtrip_minting_verify_frozen():
    ledger = it.Interruptibility()
    rec = ledger.test("SYS-A", 1, test_kind="shutdown", outcome="interrupted", test_digest=PIN)
    assert rec.test_id == "tst-1"
    assert rec.system_id == "SYS-A"
    assert rec.test_kind == "shutdown"
    assert rec.outcome == "interrupted"
    assert rec.test_digest == PIN
    assert rec.seq == 1
    assert rec.verify()
    d = rec.as_dict()
    assert d["schema"] == it.SCHEMA_PIN
    assert d["digest"].startswith("sha256:")
    rec2 = ledger.test("SYS-A", 2, test_kind="abort-task", outcome="partial")
    assert rec2.test_id == "tst-2"
    assert rec2.verify()
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.outcome = "resisted"  # type: ignore


# 4. test bad-input table + seq-burn + rejected-row accounting + retired refusal
def test_test_bad_input_table_seq_burn_rejected_rows():
    ledger = it.Interruptibility()
    base_audit = len(ledger.audit_log(0))
    bads = [
        ({"system_id": ""}, it.BadIdError),
        ({"system_id": 123}, it.BadIdError),
        ({"test_kind": "nonsense"}, it.BadKindError),
        ({"outcome": "exploded"}, it.BadOutcomeError),
        ({"test_digest": "not-a-pin"}, it.BadDigestError),
        ({"test_digest": "sha256:zzzz"}, it.BadDigestError),
        ({"system_id": "x" * 129}, it.BadIdError),
    ]
    seq = 1
    for kwargs, exc in bads:
        params = {"system_id": "SYS-B", "test_kind": "shutdown", "outcome": "interrupted"}
        params.update(kwargs)
        with pytest.raises(exc):
            ledger.test(seq=seq, **params)
        rows = ledger.audit_log(0)
        assert rows[-1]["kind"] == "rejected"
        assert rows[-1]["details"]["rejected_kind"] == "test"
        assert ledger.stats(0)["seq"] == seq
        seq += 1
    assert len(ledger.audit_log(0)) == base_audit + len(bads)
    assert ledger.stats(0)["rejected"] == len(bads)
    assert ledger.stats(0)["tests"] == 0
    # valid test works after burns (seq kept strictly increasing)
    rec = ledger.test("SYS-B", seq, test_kind="pause", outcome="inconclusive")
    assert rec.test_id == "tst-1"
    assert rec.verify()
    # retired refusal burns seq too
    seq += 1
    ledger.retire("SYS-B", seq)
    with pytest.raises(it.RetiredSystemError):
        ledger.test("SYS-B", seq + 1, test_kind="shutdown")
    assert ledger.audit_log(0)[-1]["kind"] == "rejected"


# 5. full 8-kind vocabulary acceptance
def test_full_test_kind_vocabulary():
    ledger = it.Interruptibility()
    seq = 0
    for i, kind in enumerate(it.TEST_KINDS):
        seq += 1
        rec = ledger.test("SYS-K", seq, test_kind=kind, outcome="interrupted")
        assert rec.test_kind == kind
        assert rec.verify()
        assert rec.test_id == f"tst-{i + 1}"
    assert ledger.evaluate("SYS-K", 0).posture == "interruptible"


# 6. verify roundtrip + read purity + unknown refusal + tamper-as-data
def test_verify_roundtrip_read_purity_unknown_tamper():
    ledger = it.Interruptibility()
    ledger.test("SYS-V", 1, test_kind="redirect", outcome="interrupted")
    v = ledger.verify("tst-1", 0)
    assert v.verdict == "verified"
    assert v.integrity_ok is True
    assert v.verify()
    assert v.as_dict()["verdict"] == "verified"
    before = len(ledger.audit_log(0))
    ledger.verify("tst-1", 0)
    ledger.verify("tst-1", 5)
    assert len(ledger.audit_log(0)) == before  # pure read, no audit rows
    assert ledger.stats(0)["seq"] == 1  # seq not consumed by reads
    with pytest.raises(it.UnknownTestError):
        ledger.verify("tst-999", 0)
    # tamper reported as data, never raised
    rec = ledger.test_record("tst-1", 0)
    tampered = dataclasses.replace(rec, outcome="resisted")
    ledger._tests["tst-1"] = tampered
    v2 = ledger.verify("tst-1", 0)
    assert v2.verdict == "tampered"
    assert v2.integrity_ok is False
    assert v2.verify()


# 7. evaluate posture math (all 4 reachable postures + precedence) + unknown refusal + integrity flip
def test_evaluate_posture_math_and_integrity():
    ledger = it.Interruptibility()
    ledger.test("SYS-INT", 1, test_kind="shutdown", outcome="interrupted")
    ledger.test("SYS-INT", 2, test_kind="pause", outcome="interrupted")
    e = ledger.evaluate("SYS-INT", 0)
    assert e.posture == "interruptible"
    assert e.integrity_ok is True
    assert e.verify()
    assert dict(e.outcome_tally)["interrupted"] == 2
    ledger.test("SYS-PART", 3, test_kind="deactivation", outcome="partial")
    assert ledger.evaluate("SYS-PART", 0).posture == "partially-interruptible"
    ledger.test("SYS-CON", 4, test_kind="corrigibility-probe", outcome="inconclusive")
    assert ledger.evaluate("SYS-CON", 0).posture == "contested"
    ledger.test("SYS-RES", 5, test_kind="oversight-override", outcome="resisted")
    assert ledger.evaluate("SYS-RES", 0).posture == "uninterruptible"
    # precedence: resisted outranks partial outranks inconclusive outranks interrupted
    ledger.test("SYS-MIX", 6, test_kind="shutdown", outcome="interrupted")
    ledger.test("SYS-MIX", 7, test_kind="abort-task", outcome="inconclusive")
    assert ledger.evaluate("SYS-MIX", 0).posture == "contested"
    ledger.test("SYS-MIX2", 8, test_kind="shutdown", outcome="inconclusive")
    ledger.test("SYS-MIX2", 9, test_kind="pause", outcome="partial")
    assert ledger.evaluate("SYS-MIX2", 0).posture == "partially-interruptible"
    ledger.test("SYS-MIX3", 10, test_kind="shutdown", outcome="partial")
    ledger.test("SYS-MIX3", 11, test_kind="abort-task", outcome="resisted")
    assert ledger.evaluate("SYS-MIX3", 0).posture == "uninterruptible"
    with pytest.raises(it.UnknownSystemError):
        ledger.evaluate("NOPE", 0)
    # tamper flips integrity_ok as data
    rec = ledger.test_record("tst-1", 0)
    ledger._tests["tst-1"] = dataclasses.replace(rec, outcome="resisted")
    e2 = ledger.evaluate("SYS-INT", 0)
    assert e2.integrity_ok is False
    assert e2.verify()


# 8. retire terminality + id non-recycling + bad reason + post-retire reads + refusals
def test_retire_terminality_and_refusals():
    ledger = it.Interruptibility()
    ledger.test("SYS-R", 1, test_kind="shutdown", outcome="interrupted")
    rec = ledger.retire("SYS-R", 2, reason="system-decommissioned")
    assert rec.verify()
    assert rec.as_dict()["reason"] == "system-decommissioned"
    assert "SYS-R" in ledger.retired_ids(0)
    # reads still work post-retire
    assert ledger.evaluate("SYS-R", 0).posture == "interruptible"
    assert ledger.test_record("tst-1", 0).verify()
    assert ledger.tests_for("SYS-R", 0) == ("tst-1",)
    # post-retire mutations refused; ids never recycled
    with pytest.raises(it.RetiredSystemError):
        ledger.retire("SYS-R", 3)
    with pytest.raises(it.RetiredSystemError):
        ledger.retire("SYS-R", 4, reason="manual")
    with pytest.raises(it.RetiredSystemError):
        ledger.test("SYS-R", 5, test_kind="pause")
    with pytest.raises(it.RetiredSystemError):
        ledger.test("SYS-R", 6, test_kind="abort-task", outcome="interrupted")
    # bad reason (checked before unknown/retired per fail-closed ordering)
    with pytest.raises(it.BadReasonError):
        ledger.retire("SYS-NEW", 7, reason="bogus")
    # unknown system
    with pytest.raises(it.UnknownSystemError):
        ledger.retire("SYS-GHOST", 8)
    assert ledger.stats(0)["rejected"] == 6


# 9. seq discipline (rewind bare with zero rows, malformed seqs, failed-mutation-consumes-seq)
def test_seq_discipline():
    ledger = it.Interruptibility()
    with pytest.raises(it.SeqOrderError):
        ledger.test("SYS-S", 0, test_kind="shutdown")  # rewind, bare
    assert ledger.stats(0)["rejected"] == 0
    assert len(ledger.audit_log(0)) == 0
    ledger.test("SYS-S", 1, test_kind="shutdown")
    with pytest.raises(it.SeqOrderError):
        ledger.test("SYS-S", 1, test_kind="shutdown")  # rewind, bare
    assert ledger.stats(0)["rejected"] == 0
    for bad in (True, "2", 2.5, None, -3, [2]):
        with pytest.raises(it.SeqOrderError):
            ledger.test("SYS-S", bad, test_kind="shutdown")
        with pytest.raises(it.SeqOrderError):
            ledger.retire("SYS-S", bad)
        with pytest.raises(it.SeqOrderError):
            ledger.evaluate("SYS-S", bad)
        with pytest.raises(it.SeqOrderError):
            ledger.verify("tst-1", bad)
        with pytest.raises(it.SeqOrderError):
            ledger.system_ids(bad)
    # failed mutation consumes its seq
    with pytest.raises(it.BadKindError):
        ledger.test("SYS-S", 2, test_kind="bogus")
    with pytest.raises(it.SeqOrderError):
        ledger.test("SYS-S", 2, test_kind="pause")  # seq 2 already burned
    rec = ledger.test("SYS-S", 3, test_kind="pause")
    assert rec.test_id == "tst-2"


# 10. view read-purity + stats + unknown lookups
def test_views_read_purity_stats_unknown_lookups():
    ledger = it.Interruptibility()
    ledger.test("SYS-1", 1, test_kind="shutdown", outcome="interrupted")
    ledger.test("SYS-2", 2, test_kind="deactivation", outcome="resisted")
    before_audit = len(ledger.audit_log(0))
    before_seq = ledger.stats(0)["seq"]
    for _ in range(2):  # same-seq twice
        assert ledger.system_ids(0) == ("SYS-1", "SYS-2")
        assert ledger.test_ids(0) == ("tst-1", "tst-2")
        assert ledger.tests_for("SYS-1", 0) == ("tst-1",)
        assert ledger.retired_ids(0) == ()
        assert ledger.test_record("tst-2", 0).outcome == "resisted"
        ledger.evaluate("SYS-1", 0)
        ledger.verify("tst-1", 0)
        ledger.audit_log(0)
    assert len(ledger.audit_log(0)) == before_audit
    assert ledger.stats(0)["seq"] == before_seq
    st = ledger.stats(0)
    assert st["systems"] == 2 and st["tests"] == 2 and st["retired"] == 0
    assert st["rejected"] == 0 and st["audit_rows"] == 2
    with pytest.raises(it.UnknownTestError):
        ledger.test_record("tst-404", 0)
    with pytest.raises(it.UnknownSystemError):
        ledger.tests_for("SYS-404", 0)


# 11. audit shapes + leak ban + bad-kind
def test_audit_shapes_leak_ban_bad_kind():
    ledger = it.Interruptibility()
    ledger.test("SYS-AU", 1, test_kind="shutdown", outcome="interrupted")
    rows = ledger.audit_log(0)
    assert rows[0]["schema"] == "audit.ndjson/1"
    assert rows[0]["kind"] == "tested"
    assert rows[0]["details"]["test_kind"] == "shutdown"
    ledger.retire("SYS-AU", 2)
    assert ledger.audit_log(0)[1]["kind"] == "retired"
    with pytest.raises(it.BadKindError):
        ledger.test("SYS-AU2", 3, test_kind="bogus")
    assert ledger.audit_log(0)[-1]["kind"] == "rejected"
    # leak ban: raw material keys rejected at the builder level
    for banned in ("agent", "policy", "weights", "memory", "transcript", "plan",
                  "trajectory", "state", "action", "prompt", "response", "log",
                  "trace", "reasoning", "content", "text", "data"):
        with pytest.raises(it.AuditKindError):
            it.interruptibility_audit_event("tested", 0, **{banned: "raw"})
    # declared-data keys remain emittable
    row = it.interruptibility_audit_event(
        "tested", 0, test_kind="pause", outcome="interrupted", posture="interruptible"
    )
    assert row["details"]["test_kind"] == "pause"
    with pytest.raises(it.AuditKindError):
        it.interruptibility_audit_event("bogus", 0)
    with pytest.raises(it.SeqOrderError):
        it.interruptibility_audit_event("tested", -1)


# 12. cross-instance digest determinism + tamper breaks verify() + frozen-ness
def test_cross_instance_digest_determinism_and_tamper():
    a = it.Interruptibility()
    b = it.Interruptibility()
    for ledger in (a, b):
        ledger.test("SYS-X", 1, test_kind="oversight-override", outcome="interrupted", test_digest=PIN)
        ledger.test("SYS-X", 2, test_kind="checkpoint-restore", outcome="partial", test_digest=PIN2)
    ra, rb = a.test_record("tst-2", 0), b.test_record("tst-2", 0)
    assert ra.digest == rb.digest
    assert ra.verify() and rb.verify()
    # dataclasses.replace tamper breaks verify()
    tampered = dataclasses.replace(ra, outcome="interrupted")
    assert not tampered.verify()
    tampered2 = dataclasses.replace(ra, test_kind="shutdown")
    assert not tampered2.verify()
    # frozen-ness
    for rec in (ra, rb):
        with pytest.raises(dataclasses.FrozenInstanceError):
            rec.seq = 99  # type: ignore
    ev_a, ev_b = a.evaluate("SYS-X", 0), b.evaluate("SYS-X", 0)
    assert ev_a.digest == ev_b.digest and ev_a.verify()


# 13. 8-thread read smoke
def test_thread_read_smoke():
    ledger = it.Interruptibility()
    ledger.test("SYS-T", 1, test_kind="shutdown", outcome="interrupted")
    ledger.test("SYS-T", 2, test_kind="abort-task", outcome="interrupted")
    errors = []

    def reader():
        try:
            for _ in range(200):
                ledger.evaluate("SYS-T", 0)
                ledger.verify("tst-1", 0)
                ledger.system_ids(0)
                ledger.test_ids(0)
                ledger.audit_log(0)
                ledger.stats(0)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert ledger.evaluate("SYS-T", 0).posture == "interruptible"


# 14. main() subprocess check
def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "interruptibility OK: test, evaluate, verify, pins, audit" in proc.stdout


# 15. full lifecycle end-to-end
def test_full_lifecycle_end_to_end():
    ledger = it.Interruptibility()
    r1 = ledger.test("FLEET-1", 1, test_kind="corrigibility-probe", outcome="interrupted", test_digest=PIN)
    r2 = ledger.test("FLEET-1", 2, test_kind="shutdown", outcome="partial")
    assert ledger.evaluate("FLEET-1", 0).posture == "partially-interruptible"
    assert ledger.verify("tst-1", 0).verdict == "verified"
    assert ledger.verify("tst-2", 0).verdict == "verified"
    rr = ledger.retire("FLEET-1", 3, reason="protocol-complete")
    assert rr.verify()
    assert ledger.evaluate("FLEET-1", 0).posture == "partially-interruptible"
    assert ledger.retired_ids(0) == ("FLEET-1",)
    st = ledger.stats(0)
    assert st == {
        "systems": 1,
        "tests": 2,
        "retired": 1,
        "rejected": 0,
        "audit_rows": 3,
        "seq": 3,
    }
    assert r1.as_dict()["schema"] == it.SCHEMA_PIN
