"""Tests for the control-testing lifecycle ledger (15 tests)."""

import ast
import hashlib
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parent.parent / "control_testing.py"


def load_module():
    """Import the module standalone via importlib (frozen dataclasses
    need the module registered in sys.modules first)."""
    import importlib.util

    sys.modules.pop("control_testing", None)
    spec = importlib.util.spec_from_file_location(
        "control_testing", str(MODULE_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules["control_testing"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def mod():
    return load_module()


@pytest.fixture()
def ct(mod):
    return mod.ControlTesting()


def good_digest(label="evidence"):
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def test_version_and_schema_pins():
    mod = load_module()
    assert mod.VERSION == "control-testing.v1"
    assert mod.SCHEMA == "northstar.control-testing.v1"


def test_stdlib_only():
    tree = ast.parse(MODULE_PATH.read_text())
    allowed = {
        "hashlib", "re", "threading", "dataclasses", "typing",
        "json", "canonical_json", "__future__",
    }
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    unknown = imports - allowed
    assert not unknown, f"non-stdlib imports: {unknown}"


def test_design_roundtrip_and_pins(mod, ct):
    rec = ct.design("C-1", "preventive", 1,
                    objective_digest=good_digest("obj"))
    assert rec.control_id == "C-1"
    assert rec.kind == "preventive"
    assert rec.verify()
    # digest pin is deterministic across instances
    ct2 = mod.ControlTesting()
    rec2 = ct2.design("C-1", "preventive", 1)
    assert rec.digest == rec2.digest
    # frozen
    with pytest.raises(Exception):
        rec.control_id = "C-X"  # type: ignore[misc]
    # views
    assert ct.control_ids(2) == ("C-1",)
    assert ct.design_record("C-1", 2).verify()
    assert ct.stats(2)["controls"] == 1


def test_design_bad_inputs_seq_burn(mod, ct):
    ct.design("C-1", "detective", 1)
    cases = [
        ("", "preventive", mod.BadIdError),        # empty id
        ("C-1", "preventive", mod.DuplicateControlError),
        ("C-2", "bogus", mod.BadKindError),        # bad kind
        ("C-3", 42, mod.BadKindError),             # non-str kind
        ("C-4", "preventive", mod.BadDigestError), # bad digest handled below
    ]
    seq = 1
    for cid, kind, exc in cases[:-1]:
        seq += 1
        with pytest.raises(exc):
            ct.design(cid, kind, seq)
    # bad digest
    seq += 1
    with pytest.raises(mod.BadDigestError):
        ct.design("C-5", "preventive", seq, objective_digest="not-a-digest")
    # every failure booked a rejected row + burned its seq
    rows = ct.audit_log(seq + 1)
    rejected = [r for r in rows if r["kind"] == "control-testing.rejected"]
    assert len(rejected) == 5
    assert ct.stats(seq + 1)["controls"] == 1


def test_test_lifecycle_and_vocabulary(mod, ct):
    ct.design("C-1", "corrective", 1)
    seq = 1
    for method in mod._TEST_METHODS:
        seq += 1
        rec = ct.test("C-1", f"T-{method}", method, seq, result="pass",
                      evidence_digest=good_digest(method))
        assert rec.verify()
        assert rec.method == method
    assert len(ct.tests_for("C-1", seq + 1)) == len(mod._TEST_METHODS)
    # full result vocabulary accepted
    ct.design("C-2", "compensating", seq + 1)
    seq += 1
    for i, result in enumerate(mod._TEST_RESULTS):
        seq += 1
        rec = ct.test("C-2", f"R-{i}", "sampling", seq, result=result)
        assert rec.result == result
        assert rec.verify()
    rep = ct.report(seq + 1)
    assert rep.verify()
    assert rep.n_tests == len(mod._TEST_METHODS) + 3
    assert rep.passes == len(mod._TEST_METHODS) + 1


def test_test_refusals(mod, ct):
    ct.design("C-1", "preventive", 1)
    seq = 1
    seq += 1
    with pytest.raises(mod.UnknownControlError):
        ct.test("C-9", "T-1", "inquiry", seq)
    seq += 1
    ct.test("C-1", "T-1", "inquiry", seq, result="pass")
    seq += 1
    with pytest.raises(mod.DuplicateTestError):
        ct.test("C-1", "T-1", "observation", seq)
    seq += 1
    with pytest.raises(mod.BadMethodError):
        ct.test("C-1", "T-2", "mind-reading", seq)
    seq += 1
    with pytest.raises(mod.BadResultError):
        ct.test("C-1", "T-2", "inquiry", seq, result="maybe")
    seq += 1
    with pytest.raises(mod.BadDigestError):
        ct.test("C-1", "T-2", "inquiry", seq, evidence_digest="junk")
    rows = ct.audit_log(seq + 1)
    rejected = [r for r in rows if r["kind"] == "control-testing.rejected"]
    assert len(rejected) == 5
    assert ct.stats(seq + 1)["tests"] == 1


def test_remediate_lifecycle(mod, ct):
    ct.design("C-1", "detective", 1)
    ct.test("C-1", "T-1", "inspection", 2, result="fail")
    ct.test("C-1", "T-2", "reperformance", 3, result="pass")
    seq = 3
    for i, action in enumerate(mod._REMEDIATION_ACTIONS):
        seq += 1
        ct.test("C-1", f"TF-{i}", "sampling", seq, result="fail")
        seq += 1
        rem = ct.remediate("C-1", f"TF-{i}", action, seq)
        assert rem.action == action
        assert rem.verify()
        assert rem.remediation_id.startswith("rem-")
        assert ct.remediation_record(rem.remediation_id, seq + 1).verify()
    assert ct.stats(seq + 1)["remediations"] == len(mod._REMEDIATION_ACTIONS)


def test_remediate_refusals(mod, ct):
    ct.design("C-1", "preventive", 1)
    ct.test("C-1", "T-1", "inquiry", 2, result="pass")
    ct.test("C-1", "T-2", "observation", 3, result="fail")
    seq = 3
    seq += 1
    with pytest.raises(mod.BadResultError):
        # cannot remediate a passing test
        ct.remediate("C-1", "T-1", "fix-control", seq)
    seq += 1
    with pytest.raises(mod.UnknownControlError):
        # test not booked for this control
        ct.remediate("C-1", "T-nope", "fix-control", seq)
    seq += 1
    with pytest.raises(mod.BadActionError):
        ct.remediate("C-1", "T-2", "sprinkle-magic", seq)
    seq += 1
    with pytest.raises(mod.UnknownControlError):
        ct.remediate("C-9", "T-2", "fix-control", seq)
    rows = ct.audit_log(seq + 1)
    rejected = [r for r in rows if r["kind"] == "control-testing.rejected"]
    assert len(rejected) == 4


def test_retire_terminality_and_no_recycle(mod, ct):
    ct.design("C-1", "preventive", 1)
    ct.test("C-1", "T-1", "inquiry", 2, result="pass")
    ct.retire("C-1", 3)
    # failed mutations burn their seq, so each call needs a fresh seq
    with pytest.raises(mod.RetiredControlError):
        ct.design("C-1", "detective", 4)
    with pytest.raises(mod.RetiredControlError):
        ct.test("C-1", "T-2", "inquiry", 5)
    with pytest.raises(mod.RetiredControlError):
        ct.retire("C-1", 6)
    # retired ids disappear from the live list; designs still readable
    assert ct.control_ids(5) == ()
    assert ct.design_record("C-1", 5).verify()
    assert ct.tests_for("C-1", 5) == ("T-1",)


def test_report_math_and_read_purity(mod, ct):
    ct.design("C-1", "preventive", 1)
    ct.design("C-2", "detective", 2)
    ct.test("C-1", "T-1", "inquiry", 3, result="pass")
    ct.test("C-1", "T-2", "observation", 4, result="fail")
    ct.test("C-2", "T-3", "inspection", 5, result="inconclusive")
    n_rows_before = ct.stats(6)["audit_rows"]
    rep = ct.report(6)
    assert rep.verify()
    assert (rep.passes, rep.fails, rep.inconclusive) == (1, 1, 1)
    assert rep.n_controls == 2 and rep.n_tests == 3
    assert rep.controls_with_failures == ("C-1",)
    # pure read: same seq twice, no rows written, seq not consumed
    rep2 = ct.report(6)
    assert rep2.digest == rep.digest
    assert ct.stats(6)["audit_rows"] == n_rows_before
    d = rep.as_dict()
    assert d["controls_with_failures"] == ["C-1"]
    assert d["schema"] == mod.SCHEMA


def test_seq_discipline(mod, ct):
    ct.design("C-1", "preventive", 1)
    # rewind raises bare (SeqOrderError), no rejected row, seq unconsumed
    n_rows_before = ct.stats(2)["audit_rows"]
    with pytest.raises(mod.SeqOrderError):
        ct.test("C-1", "T-1", "inquiry", 1, result="pass")
    with pytest.raises(mod.SeqOrderError):
        ct.test("C-1", "T-1", "inquiry", 0, result="pass")
    assert ct.stats(2)["audit_rows"] == n_rows_before
    # malformed seqs
    for bad in (True, "2", 2.0, -1, None):
        with pytest.raises(mod.SeqOrderError):
            ct.test("C-1", "T-1", "inquiry", bad, result="pass")
    # seq advances only via mutations / rejected rows
    ct.test("C-1", "T-1", "inquiry", 2, result="pass")
    assert ct.stats(3)["audit_rows"] == n_rows_before + 1


def test_audit_shapes_leak_ban_and_bad_kind(mod, ct):
    rec = ct.design("C-1", "preventive", 1)
    ct.test("C-1", "T-1", "inquiry", 2, result="fail")
    rem = ct.remediate("C-1", "T-1", "redesign", 3)
    rows = ct.audit_log(4)
    kinds = [r["kind"] for r in rows]
    assert kinds == ["control-testing.control-designed",
                     "control-testing.tested",
                     "control-testing.remediated"]
    for r in rows:
        assert r["audit_version"] == "audit.ndjson/1"
        assert r["schema"] == mod.SCHEMA
        assert r["version"] == mod.VERSION
    # banned raw-content keys never cross the audit boundary
    with pytest.raises(mod.AuditKindError):
        mod.control_testing_audit_event(
            "tested", {"evidence": "raw text"}, 4)
    with pytest.raises(mod.AuditKindError):
        mod.control_testing_audit_event("nope", {}, 4)
    # digest pins survive tamper reporting as data
    tampered = ct.test_record("T-1", 4)
    object.__setattr__(tampered, "result", "pass")
    assert not tampered.verify()


def test_cross_instance_digest_determinism(mod, ct):
    ct.design("C-1", "corrective", 1)
    ct.test("C-1", "T-1", "reperformance", 2, result="fail")
    rem = ct.remediate("C-1", "T-1", "retrain", 3)
    other = mod.ControlTesting()
    other.design("C-1", "corrective", 1)
    other.test("C-1", "T-1", "reperformance", 2, result="fail")
    rem2 = other.remediate("C-1", "T-1", "retrain", 3)
    assert rem.digest == rem2.digest
    assert ct.report(4).digest == other.report(4).digest
    # audit rows carry the same kinds and digests in both ledgers
    rows_a = ct.audit_log(4)
    rows_b = other.audit_log(4)
    assert [r["kind"] for r in rows_a] == [r["kind"] for r in rows_b]


def test_concurrency_and_frozen_records(mod, ct):
    ct.design("C-1", "preventive", 1)
    seq = 1
    for i in range(8):
        seq += 1
        ct.test("C-1", f"TC-{i}", "sampling", seq, result="pass")
    read_seq = seq + 1
    results = []
    def worker():
        results.append(ct.report(read_seq).digest)
        results.append(ct.test_record("TC-0", read_seq).result)
    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 16
    assert len(set(results[::2])) == 1
    assert all(r == "pass" for r in results[1::2])
    # frozen records reject attribute assignment
    rec = ct.test_record("TC-0", read_seq)
    with pytest.raises(Exception):
        rec.result = "fail"  # type: ignore[misc]
    rem = ct.design_record("C-1", read_seq)
    with pytest.raises(Exception):
        rem.kind = "detective"  # type: ignore[misc]


def test_main_subprocess():
    proc = subprocess.run([sys.executable, str(MODULE_PATH)],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "control-testing OK" in proc.stdout
