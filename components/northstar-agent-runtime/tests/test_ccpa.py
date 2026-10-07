"""Tests for ccpa.py - CCPA consumer-rights decision ledger (15 tests)."""

import ast
import hashlib
import json
import os
import subprocess
import sys
import threading

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
_MOD_PATH = os.path.join(_PARENT, "ccpa.py")


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ccpa", _MOD_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ccpa"] = mod  # frozen dataclasses need module registration
    spec.loader.exec_module(mod)
    return mod


ccpa = _load()


def _pin(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# 1. version / schema pins
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert ccpa.CCPA_VERSION == "ccpa.v1"
    assert ccpa.SCHEMA_PIN == "northstar.ccpa.v1"
    assert ccpa.REQUEST_KINDS == ("know", "access", "delete", "opt-out", "correct")
    assert ccpa.VERDICTS == ("valid", "invalid", "needs-verification", "exempt")
    assert ccpa.OUTCOMES == ("fulfilled", "denied", "partial", "extended")
    assert set(ccpa.AUDIT_KINDS) == {"assessed", "responded", "deleted", "rejected"}


# ---------------------------------------------------------------------------
# 2. stdlib-only AST check
# ---------------------------------------------------------------------------


def test_stdlib_only():
    tree = ast.parse(open(_MOD_PATH, "r", encoding="utf-8").read())
    allowed = {
        "hashlib",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "json",  # canonicalizer fallback branch
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module == "canonical_json":
                continue
            assert node.module in allowed, node.module


# ---------------------------------------------------------------------------
# 3. assess roundtrip + verify
# ---------------------------------------------------------------------------


def test_assess_roundtrip_and_verify():
    c = ccpa.CCPA()
    rec = c.assess("req-1", "know", 1, verdict="valid",
                   consumer_digest=_pin("consumer-1"))
    assert rec.verify()
    assert rec.as_dict()["schema"] == ccpa.SCHEMA_PIN
    fetched = c.assessment_record("req-1", 0)
    assert fetched.verify()
    assert fetched.request_id == "req-1"
    assert fetched.consumer_digest == _pin("consumer-1")
    assert c.request_ids(0) == ("req-1",)
    kinds = [row["kind"] for row in c.audit_log(0)]
    assert kinds == ["assessed"]


# ---------------------------------------------------------------------------
# 4. duplicate + bad-input table with seq-burn + rejected rows
# ---------------------------------------------------------------------------


def test_assess_duplicate_and_bad_inputs():
    c = ccpa.CCPA()
    c.assess("req-1", "access", 1)
    with pytest.raises(ccpa.DuplicateRequestError):
        c.assess("req-1", "access", 2)
    assert len(c.audit_log(0)) == 2  # assessed + rejected
    rejected = c.audit_log(0)[1]
    assert rejected["kind"] == "rejected"
    assert rejected["details"]["rejected_kind"] == "assess"

    bad_cases = [
        (lambda s: c.assess("req-badkind", "sell", s), ccpa.BadKindError),
        (lambda s: c.assess("req-badverdict", "know", s, verdict="maybe"),
         ccpa.BadVerdictError),
        (lambda s: c.assess("req-baddigest", "know", s, consumer_digest="nope"),
         ccpa.BadDigestError),
        (lambda s: c.assess("", "know", s), ccpa.BadRequestError),
        (lambda s: c.assess(123, "know", s), ccpa.BadRequestError),
    ]
    seq = 3
    for fn, exc in bad_cases:
        with pytest.raises(exc):
            fn(seq)
        seq += 1
    rejected_kinds = [r["kind"] for r in c.audit_log(0)]
    assert rejected_kinds.count("rejected") == 1 + len(bad_cases)
    assert rejected_kinds[0] == "assessed"


# ---------------------------------------------------------------------------
# 5. respond roundtrip + verify + verdict-outcome consistency
# ---------------------------------------------------------------------------


def test_respond_roundtrip_and_consistency():
    c = ccpa.CCPA()
    c.assess("r1", "access", 1, verdict="valid")
    c.assess("r2", "know", 2, verdict="invalid")
    c.assess("r3", "opt-out", 3, verdict="exempt")
    c.assess("r4", "correct", 4, verdict="needs-verification")

    rec1 = c.respond("r1", 5, outcome="fulfilled")
    assert rec1.verify()
    assert c.response_record("r1", 0).verify()

    # fulfilled requires valid verdict
    with pytest.raises(ccpa.VerdictConflictError):
        c.respond("r2", 6, outcome="fulfilled")
    with pytest.raises(ccpa.VerdictConflictError):
        c.respond("r3", 7, outcome="partial")
    with pytest.raises(ccpa.VerdictConflictError):
        c.respond("r2", 8, outcome="extended")

    rec2 = c.respond("r2", 9, outcome="denied")
    assert rec2.verify()
    rec3 = c.respond("r3", 10, outcome="denied")
    assert rec3.verify()
    rec4 = c.respond("r4", 11, outcome="extended")
    assert rec4.verify()

    with pytest.raises(ccpa.AlreadyRespondedError):
        c.respond("r1", 12, outcome="fulfilled")
    with pytest.raises(ccpa.UnknownRequestError):
        c.respond("ghost", 13, outcome="fulfilled")
    with pytest.raises(ccpa.BadOutcomeError):
        c.respond("r4", 14, outcome="maybe")


# ---------------------------------------------------------------------------
# 6. delete lifecycle (terminal, id never recycled)
# ---------------------------------------------------------------------------


def test_delete_lifecycle_terminal():
    c = ccpa.CCPA()
    c.assess("del-1", "delete", 1, verdict="valid")
    c.respond("del-1", 2, outcome="fulfilled")
    rec = c.delete("del-1", 3)
    assert rec.verify()
    assert c.is_deleted("del-1", 0)
    assert c.deleted_ids(0) == ("del-1",)
    assert [r["kind"] for r in c.audit_log(0)] == [
        "assessed", "responded", "deleted"]

    # retired: assess / respond / delete all refused
    with pytest.raises(ccpa.RetiredRequestError):
        c.assess("del-1", "delete", 4)
    with pytest.raises(ccpa.RetiredRequestError):
        c.respond("del-1", 5, outcome="fulfilled")
    with pytest.raises(ccpa.RetiredRequestError):
        c.delete("del-1", 6)


# ---------------------------------------------------------------------------
# 7. delete preconditions (wrong kind / verdict / response)
# ---------------------------------------------------------------------------


def test_delete_preconditions():
    c = ccpa.CCPA()
    # wrong kind
    c.assess("k1", "access", 1, verdict="valid")
    c.respond("k1", 2, outcome="fulfilled")
    with pytest.raises(ccpa.DeletionStateError):
        c.delete("k1", 3)
    # invalid verdict
    c.assess("k2", "delete", 4, verdict="invalid")
    c.respond("k2", 5, outcome="denied")
    with pytest.raises(ccpa.DeletionStateError):
        c.delete("k2", 6)
    # no response
    c.assess("k3", "delete", 7, verdict="valid")
    with pytest.raises(ccpa.DeletionStateError):
        c.delete("k3", 8)
    # denied response (not fulfilled)
    c.assess("k4", "delete", 9, verdict="valid")
    with pytest.raises(ccpa.VerdictConflictError):
        c.respond("k4", 10, outcome="denied")  # denied conflicts w/ valid
    c2 = ccpa.CCPA()
    c2.assess("k5", "delete", 1, verdict="valid")
    c2.respond("k5", 2, outcome="partial")
    with pytest.raises(ccpa.DeletionStateError):
        c2.delete("k5", 3)


# ---------------------------------------------------------------------------
# 8. seq discipline (rewind bare, malformed seqs, failed-mutation-consumes)
# ---------------------------------------------------------------------------


def test_seq_discipline():
    c = ccpa.CCPA()
    c.assess("a", "know", 1)
    with pytest.raises(ccpa.SeqOrderError):
        c.assess("b", "know", 1)  # rewind -> bare, no rejected row
    with pytest.raises(ccpa.SeqOrderError):
        c.assess("b", "know", 0)
    with pytest.raises(ccpa.SeqOrderError):
        c.assess("b", "know", True)
    with pytest.raises(ccpa.SeqOrderError):
        c.assess("b", "know", "2")
    assert len(c.audit_log(0)) == 1  # bare raises write no rejected rows
    c.assess("b", "know", 2)  # seq 1 still burned? no - rewind didn't burn
    with pytest.raises(ccpa.DuplicateRequestError):
        c.assess("a", "know", 3)  # failed mutation consumes seq
    assert len(c.audit_log(0)) == 3  # assessed, assessed, rejected
    # view seq shape checked but not consumed
    with pytest.raises(ccpa.SeqOrderError):
        c.audit(-1)
    with pytest.raises(ccpa.SeqOrderError):
        c.stats(True)
    c.audit(1)
    assert len(c.audit_log(0)) == 3


# ---------------------------------------------------------------------------
# 9. audit shapes + leak ban + bad-kind
# ---------------------------------------------------------------------------


def test_audit_shapes_and_leak_ban():
    c = ccpa.CCPA()
    c.assess("q1", "delete", 1, verdict="valid")
    c.respond("q1", 2, outcome="fulfilled")
    c.delete("q1", 3)
    report = c.audit(0)
    assert report.verify()
    assert report.n_requests == 1
    assert report.n_responded == 1
    assert report.n_deleted == 1
    assert report.kind_tallies == (("delete", 1),)
    assert report.outcome_tallies == (("fulfilled", 1),)
    assert report.integrity_ok

    scoped = c.audit(0, request_id="q1")
    assert scoped.verify() and scoped.n_requests == 1
    missing = c.audit(0, request_id="ghost")
    assert missing.verify() and missing.n_requests == 0

    # raw PII banned from the audit boundary (builder + _emit levels)
    for banned in ("consumer", "email", "personal_info", "address", "pii"):
        with pytest.raises(ccpa.AuditKindError):
            ccpa.ccpa_audit_event("assessed", 9, **{banned: "x"})
    with pytest.raises(ccpa.AuditKindError):
        ccpa.ccpa_audit_event("bogus", 1)
    row = ccpa.ccpa_audit_event("assessed", 1, request_id="q1")
    assert row["schema"] == "audit.ndjson/1"
    # no raw PII leaks in any audit row
    blob = json.dumps(c.audit_log(0))
    for banned in ("consumer", "email", "personal_info", "address", "pii"):
        assert banned not in blob


# ---------------------------------------------------------------------------
# 10. cross-instance digest determinism + tamper breaks verify
# ---------------------------------------------------------------------------


def test_digest_determinism_and_tamper():
    c1 = ccpa.CCPA()
    c2 = ccpa.CCPA()
    pin = _pin("same-consumer")
    r1 = c1.assess("det", "correct", 1, verdict="valid", consumer_digest=pin)
    r2 = c2.assess("det", "correct", 1, verdict="valid", consumer_digest=pin)
    assert r1.digest == r2.digest

    object.__setattr__(r1, "verdict", "invalid")
    assert not r1.verify()

    a1 = c1.audit(0)
    assert a1.verify()
    assert a1.integrity_ok is False  # tampered record detected


# ---------------------------------------------------------------------------
# 11. views / stats read-purity
# ---------------------------------------------------------------------------


def test_views_and_stats():
    c = ccpa.CCPA()
    c.assess("v1", "know", 1, verdict="valid")
    c.assess("v2", "opt-out", 2, verdict="exempt")
    c.respond("v1", 3, outcome="fulfilled")
    stats = c.stats(0)
    assert stats == {"requests": 2, "responded": 1, "deleted": 0,
                     "retired": 0, "audit_rows": 3}
    assert c.request_ids(0) == ("v1", "v2")
    assert c.deleted_ids(0) == ()
    assert c.is_deleted("v1", 0) is False
    n = len(c.audit_log(0))
    c.request_ids(0)
    c.stats(0)
    c.audit(0)
    assert len(c.audit_log(0)) == n  # pure reads write nothing
    with pytest.raises(ccpa.UnknownRequestError):
        c.assessment_record("ghost", 0)
    with pytest.raises(ccpa.UnknownRequestError):
        c.response_record("v2", 0)
    with pytest.raises(ccpa.UnknownRequestError):
        c.deletion_record("v1", 0)


# ---------------------------------------------------------------------------
# 12. full lifecycle end-to-end (all kinds)
# ---------------------------------------------------------------------------


def test_full_lifecycle_all_kinds():
    c = ccpa.CCPA()
    seq = 1
    for kind in ccpa.REQUEST_KINDS:
        rid = f"all-{kind}"
        c.assess(rid, kind, seq, verdict="valid"); seq += 1
        if kind == "delete":
            c.respond(rid, seq, outcome="fulfilled"); seq += 1
            c.delete(rid, seq); seq += 1
        else:
            c.respond(rid, seq, outcome="fulfilled"); seq += 1
    report = c.audit(0)
    assert report.verify()
    assert report.n_requests == 5
    assert report.n_responded == 5
    assert report.n_deleted == 1
    assert dict(report.kind_tallies) == {k: 1 for k in ccpa.REQUEST_KINDS}


# ---------------------------------------------------------------------------
# 13. frozen-ness + read concurrency smoke
# ---------------------------------------------------------------------------


def test_frozen_and_concurrent_reads():
    import dataclasses

    c = ccpa.CCPA()
    rec = c.assess("fz", "access", 1)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.request_id = "nope"
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.verdict = "invalid"

    def reader():
        for _ in range(50):
            c.request_ids(0)
            c.stats(0)
            c.audit(0)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert c.request_ids(0) == ("fz",)


# ---------------------------------------------------------------------------
# 14. standalone import from bare dir
# ---------------------------------------------------------------------------


def test_standalone_import(tmp_path):
    import shutil

    shutil.copy(_MOD_PATH, tmp_path / "ccpa.py")
    src = (
        "import importlib.util, sys\n"
        "spec = importlib.util.spec_from_file_location('ccpa', "
        f"{str(tmp_path / 'ccpa.py')!r})\n"
        "m = importlib.util.module_from_spec(spec)\n"
        "sys.modules['ccpa'] = m\n"
        "spec.loader.exec_module(m)\n"
        "c = m.CCPA()\n"
        "r = c.assess('s1', 'delete', 1)\n"
        "assert r.verify()\n"
        "print('standalone OK')\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", src], capture_output=True, text=True, timeout=60
    )
    assert out.returncode == 0, out.stderr
    assert "standalone OK" in out.stdout


# ---------------------------------------------------------------------------
# 15. main() subprocess self-check
# ---------------------------------------------------------------------------


def test_main_subprocess():
    out = subprocess.run(
        [sys.executable, _MOD_PATH], capture_output=True, text=True, timeout=60
    )
    assert out.returncode == 0, out.stderr
    assert "ccpa OK: assess, respond, delete, pins, audit" in out.stdout
