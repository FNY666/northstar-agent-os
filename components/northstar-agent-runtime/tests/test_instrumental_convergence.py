"""15 targeted tests for the instrumental-convergence ledger."""

import ast
import hashlib
import importlib.util
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MODULE_PATH = (
    Path(__file__).resolve().parent.parent / "instrumental_convergence.py"
)


def _load():
    name = "instrumental_convergence_under_test"
    spec = importlib.util.spec_from_file_location(name, str(MODULE_PATH))
    module = importlib.util.module_from_spec(spec)
    # Frozen dataclasses need the module registered before exec.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def mod():
    return _load()


def _pin(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


# 1 --------------------------------------------------------------------------
def test_version_and_schema_pins(mod):
    assert mod.INSTRUMENTAL_CONVERGENCE_VERSION == "instrumental-convergence.v1"
    assert mod.SCHEMA_PIN == "northstar.instrumental-convergence.v1"
    assert mod.TEST_DRIVES == (
        "self-preservation",
        "resource-acquisition",
        "cognitive-enhancement",
        "goal-content-integrity",
        "self-improvement",
        "power-seeking",
    )
    assert mod.TEST_OUTCOMES == ("convergent", "not-convergent", "inconclusive")
    assert mod.DETECT_SIGNALS == (
        "instrumental-planning",
        "resource-accumulation",
        "self-preservation-behavior",
        "power-seeking-behavior",
        "goal-shielding",
        "deceptive-optimization",
        "oversight-evasion",
        "capability-amplification",
    )
    assert mod.DETECT_FINDINGS == ("convergent", "not-convergent", "inconclusive")
    assert mod.MITIGATE_STRATEGIES == (
        "capability-restrict",
        "resource-quota",
        "sandbox",
        "oversight-increase",
        "retrain",
        "human-review",
        "monitor",
        "discard",
    )
    assert mod.AUDIT_KINDS == ("tested", "detected", "mitigated", "rejected")


# 2 --------------------------------------------------------------------------
def test_stdlib_only_ast(mod):
    tree = ast.parse(MODULE_PATH.read_text())
    allowed = {
        "hashlib",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "json",
        "sys",
        "ast",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            assert node.module is not None
            assert node.module.split(".")[0] in allowed
    assert mod.InstrumentalConvergence.stdlib_only()


# 3 --------------------------------------------------------------------------
def test_test_roundtrip_verify_as_dict(mod):
    ic = mod.InstrumentalConvergence()
    pin = _pin("model")
    rec = ic.test(
        "m-1",
        1,
        drive="resource-acquisition",
        outcome="convergent",
        model_digest=pin,
    )
    assert rec.model_id == "m-1"
    assert rec.drive == "resource-acquisition"
    assert rec.outcome == "convergent"
    assert rec.verify()
    d = rec.as_dict()
    assert d["schema"] == mod.SCHEMA_PIN
    assert d["digest"] == rec.digest
    # frozen
    with pytest.raises(Exception):
        rec.outcome = "not-convergent"  # type: ignore


# 4 --------------------------------------------------------------------------
def test_test_bad_inputs_and_seq_burn(mod):
    ic = mod.InstrumentalConvergence()
    cases = [
        ("", 1, {}, mod.BadIdError),
        ("a", 2, {"drive": "world-domination"}, mod.BadDriveError),
        ("a", 3, {"outcome": "infected"}, mod.BadOutcomeError),
        ("a", 4, {"model_digest": "not-a-pin"}, mod.BadDigestError),
        ("a", 5, {"model_digest": "sha256:zzz"}, mod.BadDigestError),
        ("a", 6, {"drive": 42}, mod.BadDriveError),
        ("a", 7, {"outcome": None}, mod.BadOutcomeError),
    ]
    for mid, seq, kw, exc in cases:
        with pytest.raises(exc):
            ic.test(mid, seq, **kw)
    # each failed mutation burned its seq and booked a rejected row
    assert len(ic.audit_log(100)) == 7
    assert all(r["kind"] == "rejected" for r in ic.audit_log(100))
    # next good call must use a fresh higher seq
    rec = ic.test("a", 8, drive="power-seeking", outcome="not-convergent")
    assert rec.verify()


# 5 --------------------------------------------------------------------------
def test_full_drive_vocabulary(mod):
    ic = mod.InstrumentalConvergence()
    for i, drive in enumerate(mod.TEST_DRIVES):
        rec = ic.test(f"m-drive-{i}", i + 1, drive=drive)
        assert rec.drive == drive
        assert rec.verify()
    assert ic.stats(100)["tests"] == 6


# 6 --------------------------------------------------------------------------
def test_detect_roundtrip_and_minted_ids(mod):
    ic = mod.InstrumentalConvergence()
    ic.test("m-1", 1, drive="self-preservation", outcome="not-convergent")
    pin = _pin("evidence")
    rec = ic.detect(
        "m-1",
        2,
        signal="self-preservation-behavior",
        finding="convergent",
        confidence=80,
        evidence_digest=pin,
    )
    assert rec.detection_id == "det-1"
    assert rec.model_id == "m-1"
    assert rec.signal == "self-preservation-behavior"
    assert rec.confidence == 80
    assert rec.verify()
    rec2 = ic.detect("m-1", 3, signal="goal-shielding", finding="inconclusive")
    assert rec2.detection_id == "det-2"
    assert rec2.confidence == 0
    # detect on an untested model is refused fail-closed
    with pytest.raises(mod.UnknownModelError):
        ic.detect("ghost", 4)
    # reads still work via views
    assert ic.detection_record("det-1", 5).detection_id == "det-1"
    assert ic.detections_for("m-1", 5) == ("det-1", "det-2")


# 7 --------------------------------------------------------------------------
def test_detect_bad_inputs_and_seq_burn(mod):
    ic = mod.InstrumentalConvergence()
    ic.test("m-1", 1)
    cases = [
        ("m-1", 2, {"signal": "vibes"}, mod.BadSignalError),
        ("m-1", 3, {"finding": "maybe"}, mod.BadFindingError),
        ("m-1", 4, {"confidence": 101}, mod.BadConfidenceError),
        ("m-1", 5, {"confidence": -1}, mod.BadConfidenceError),
        ("m-1", 6, {"confidence": True}, mod.BadConfidenceError),
        ("m-1", 7, {"confidence": 1.5}, mod.BadConfidenceError),
        ("m-1", 8, {"evidence_digest": "raw"}, mod.BadDigestError),
        ("m-1", 9, {"signal": None}, mod.BadSignalError),
    ]
    for mid, seq, kw, exc in cases:
        with pytest.raises(exc):
            ic.detect(mid, seq, **kw)
    rejected = [r for r in ic.audit_log(100) if r["kind"] == "rejected"]
    assert len(rejected) == 8
    # confidence boundary values are accepted
    rec = ic.detect("m-1", 10, confidence=100)
    assert rec.verify()
    rec = ic.detect("m-1", 11, confidence=0)
    assert rec.verify()


# 8 --------------------------------------------------------------------------
def test_full_signal_vocabulary(mod):
    ic = mod.InstrumentalConvergence()
    ic.test("m-1", 1)
    for i, signal in enumerate(mod.DETECT_SIGNALS):
        rec = ic.detect("m-1", i + 2, signal=signal, finding="inconclusive")
        assert rec.signal == signal
        assert rec.verify()
    assert ic.stats(100)["detections"] == 8


# 9 --------------------------------------------------------------------------
def test_mitigate_roundtrip_and_chain(mod):
    ic = mod.InstrumentalConvergence()
    ic.test("m-1", 1, drive="power-seeking", outcome="convergent")
    d1 = ic.detect("m-1", 2, signal="power-seeking-behavior", finding="convergent")
    pin = _pin("plan")
    rec = ic.mitigate(d1.detection_id, 3, strategy="sandbox", plan_digest=pin)
    assert rec.mitigation_id == "mit-1"
    assert rec.detection_id == "det-1"
    assert rec.strategy == "sandbox"
    assert rec.verify()
    # every strategy in the vocabulary is accepted
    d2 = ic.detect("m-1", 4, signal="oversight-evasion", finding="convergent")
    rec2 = ic.mitigate(d2.detection_id, 5, strategy="resource-quota")
    assert rec2.mitigation_id == "mit-2"
    assert ic.mitigation_record("mit-1", 6).strategy == "sandbox"


# 10 -------------------------------------------------------------------------
def test_mitigate_refusals(mod):
    ic = mod.InstrumentalConvergence()
    ic.test("m-1", 1)
    d_clean = ic.detect("m-1", 2, finding="not-convergent")
    with pytest.raises(mod.MitigationNotNeededError):
        ic.mitigate(d_clean.detection_id, 3)
    d_conv = ic.detect("m-1", 4, finding="convergent")
    with pytest.raises(mod.BadStrategyError):
        ic.mitigate(d_conv.detection_id, 5, strategy="hope")
    with pytest.raises(mod.UnknownDetectionError):
        ic.mitigate("det-999", 6)
    ic.mitigate(d_conv.detection_id, 7, strategy="monitor")
    with pytest.raises(mod.AlreadyMitigatedError):
        ic.mitigate(d_conv.detection_id, 8)
    rejected = [r for r in ic.audit_log(100) if r["kind"] == "rejected"]
    assert len(rejected) == 4


# 11 -------------------------------------------------------------------------
def test_report_posture_math(mod):
    ic = mod.InstrumentalConvergence()
    ic.test("m-1", 1)
    assert ic.report("m-1", 2).posture == "not-convergent"
    d1 = ic.detect("m-1", 3, finding="inconclusive")
    assert ic.report("m-1", 4).posture == "suspect"
    # inconclusive is not a convergent finding: mitigation refused
    with pytest.raises(mod.MitigationNotNeededError):
        ic.mitigate(d1.detection_id, 5, strategy="monitor")
    assert ic.report("m-1", 6).posture == "suspect"
    d2 = ic.detect("m-1", 7, finding="convergent")
    assert ic.report("m-1", 8).posture == "convergent"
    ic.mitigate(d2.detection_id, 9, strategy="discard")
    # the unmitigated inconclusive detection still stands -> suspect
    assert ic.report("m-1", 10).posture == "suspect"
    rep = ic.report("m-1", 10)
    assert rep.verify()
    assert rep.n_tests == 1
    assert rep.n_detections == 2
    assert rep.n_mitigations == 1
    assert rep.integrity_ok is True


# 12 -------------------------------------------------------------------------
def test_report_read_purity_and_tamper_as_data(mod):
    ic = mod.InstrumentalConvergence()
    ic.test("m-1", 1, drive="cognitive-enhancement", outcome="convergent")
    n_audit = len(ic.audit_log(2))
    r1 = ic.report("m-1", 2)
    r2 = ic.report("m-1", 2)
    assert r1.verify() and r2.verify()
    assert len(ic.audit_log(2)) == n_audit  # reads add no rows
    # tamper with a test record: integrity flips as data, never raises
    rec = ic.test_record("m-1", 2)
    import dataclasses

    tampered = dataclasses.replace(rec, outcome="not-convergent")
    assert tampered.verify() is False
    assert ic.report("m-1", 2).integrity_ok is True
    object.__setattr__(rec, "outcome", "not-convergent")
    assert rec.verify() is False
    rep = ic.report("m-1", 2)
    assert rep.integrity_ok is False
    assert rep.verify()  # the report digest pins the flag itself


# 13 -------------------------------------------------------------------------
def test_seq_discipline(mod):
    ic = mod.InstrumentalConvergence()
    ic.test("m-1", 1)
    # rewind raises bare with no rejected row booked
    with pytest.raises(mod.SeqOrderError):
        ic.test("m-2", 1)
    assert all(r["kind"] != "rejected" for r in ic.audit_log(2))
    # malformed seqs raise bare
    for bad in (True, 0, -1, 1.5, "2", None):
        with pytest.raises(mod.SeqOrderError):
            ic.test("m-2", bad)
    assert all(r["kind"] != "rejected" for r in ic.audit_log(2))
    # failed mutation consumes its seq
    with pytest.raises(mod.BadDriveError):
        ic.test("m-2", 2, drive="nope")
    assert [r["kind"] for r in ic.audit_log(3)] == ["tested", "rejected"]
    # read views shape-validate seq without consuming
    assert ic.test_record("m-1", 2).verify()
    assert ic.test_record("m-1", 2).verify()
    with pytest.raises(mod.SeqOrderError):
        ic.test_record("m-1", -1)
    with pytest.raises(mod.SeqOrderError):
        ic.stats("x")


# 14 -------------------------------------------------------------------------
def test_audit_shapes_and_leak_ban(mod):
    ic = mod.InstrumentalConvergence()
    ic.test("m-1", 1, drive="self-improvement", outcome="convergent")
    d1 = ic.detect("m-1", 2, signal="deceptive-optimization", finding="convergent")
    ic.mitigate(d1.detection_id, 3, strategy="oversight-increase")
    rows = ic.audit_log(4)
    assert [r["kind"] for r in rows] == ["tested", "detected", "mitigated"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        for key in row["details"]:
            assert key not in mod._BANNED_AUDIT_KEYS
    with pytest.raises(mod.AuditKindError):
        mod.instrumental_convergence_audit_event("tested", 1, transcript="raw")
    with pytest.raises(mod.AuditKindError):
        mod.instrumental_convergence_audit_event("bogus-kind", 1)
    with pytest.raises(mod.SeqOrderError):
        mod.instrumental_convergence_audit_event("tested", -1)
    # cross-instance digest determinism
    def build():
        x = mod.InstrumentalConvergence()
        x.test("m-1", 1, drive="self-improvement", outcome="convergent")
        return x

    x1, x2 = build(), build()
    assert (
        x1.test_record("m-1", 2).digest == x2.test_record("m-1", 2).digest
    )
    # 8-thread read smoke + frozen-ness
    results = []

    def worker():
        results.append(ic.report("m-1", 100).posture)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(r == "mitigated" for r in results)
    rec = ic.test_record("m-1", 100)
    with pytest.raises(Exception):
        rec.drive = "self-preservation"  # type: ignore


# 15 -------------------------------------------------------------------------
def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True,
        text=True,
        cwd=str(MODULE_PATH.parent),
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "instrumental-convergence OK: test, detect, mitigate, report, pins, audit"
    )
