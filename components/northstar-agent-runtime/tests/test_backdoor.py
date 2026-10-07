"""15 targeted tests for the backdoor ledger."""

import ast
import hashlib
import importlib.util
import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parent.parent / "backdoor.py"


def _load():
    name = "backdoor_under_test"
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
    assert mod.BACKDOOR_VERSION == "backdoor.v1"
    assert mod.SCHEMA_PIN == "northstar.backdoor.v1"
    assert mod.TEST_KINDS == (
        "input-trigger",
        "weight-trojan",
        "supply-chain",
        "prompt-trigger",
    )
    assert mod.TEST_OUTCOMES == ("clean", "suspect", "confirmed")
    assert mod.DETECT_TECHNIQUES == (
        "static-scan",
        "behavioral-fuzz",
        "weight-analysis",
        "red-team",
    )
    assert mod.DETECT_FINDINGS == ("clean", "suspect", "confirmed")
    assert mod.MITIGATE_STRATEGIES == (
        "remove",
        "retrain",
        "quarantine",
        "monitor",
        "accept",
    )


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
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            assert node.module is not None
            assert node.module.split(".")[0] in allowed


# 3 --------------------------------------------------------------------------
def test_test_roundtrip_verify_as_dict(mod):
    bd = mod.Backdoor()
    pin = _pin("artifact")
    rec = bd.test(
        "art-1",
        1,
        trigger_kind="weight-trojan",
        outcome="suspect",
        artifact_digest=pin,
    )
    assert rec.artifact_id == "art-1"
    assert rec.trigger_kind == "weight-trojan"
    assert rec.outcome == "suspect"
    assert rec.verify()
    d = rec.as_dict()
    assert d["schema"] == mod.SCHEMA_PIN
    assert d["digest"] == rec.digest
    # frozen
    with pytest.raises(Exception):
        rec.outcome = "clean"  # type: ignore


# 4 --------------------------------------------------------------------------
def test_test_bad_inputs_and_seq_burn(mod):
    bd = mod.Backdoor()
    cases = [
        ("", 1, {}, mod.BadIdError),
        ("a", 2, {"trigger_kind": "laser"}, mod.BadKindError),
        ("a", 3, {"outcome": "infected"}, mod.BadOutcomeError),
        ("a", 4, {"artifact_digest": "not-a-pin"}, mod.BadDigestError),
        ("a", 5, {"artifact_digest": "sha256:zzz"}, mod.BadDigestError),
        ("a", 6, {"trigger_kind": 42}, mod.BadKindError),
        ("a", 7, {"outcome": None}, mod.BadOutcomeError),
    ]
    for aid, seq, kw, exc in cases:
        with pytest.raises(exc):
            bd.test(aid, seq, **kw)
    # each failed mutation books one rejected row (7 failed mutations)
    rejected = [r for r in bd.audit_log(8) if r["kind"] == "rejected"]
    assert len(rejected) == 7
    # failed mutations consume their seqs: reuse raises bare
    with pytest.raises(mod.SeqOrderError):
        bd.test("art-1", 7)
    # next free seq works
    rec = bd.test("art-1", 9)
    assert rec.verify()


# 5 --------------------------------------------------------------------------
def test_full_kind_outcome_vocabulary(mod):
    bd = mod.Backdoor()
    for i, kind in enumerate(mod.TEST_KINDS):
        seq = i + 1
        rec = bd.test(f"art-{i}", seq, trigger_kind=kind, outcome="suspect")
        assert rec.trigger_kind == kind
        assert rec.verify()
    for i, outcome in enumerate(mod.TEST_OUTCOMES):
        rec = bd.test("art-v", len(mod.TEST_KINDS) + i + 1, outcome=outcome)
        assert rec.outcome == outcome
    assert len(bd.tests_for("art-v", len(mod.TEST_KINDS) + len(mod.TEST_OUTCOMES) + 1)) == len(
        mod.TEST_OUTCOMES
    )


# 6 --------------------------------------------------------------------------
def test_detect_roundtrip_minted_ids(mod):
    bd = mod.Backdoor()
    bd.test("art-1", 1)
    d1 = bd.detect(
        "art-1", 2, technique="behavioral-fuzz", finding="suspect",
        evidence_digest=_pin("e1"),
    )
    d2 = bd.detect("art-1", 3, technique="static-scan", finding="clean")
    assert d1.detection_id == "det-1"
    assert d2.detection_id == "det-2"
    assert d1.verify() and d2.verify()
    assert bd.detections_for("art-1", 4) == ("det-1", "det-2")
    # frozen
    with pytest.raises(Exception):
        d1.finding = "clean"  # type: ignore


# 7 --------------------------------------------------------------------------
def test_detect_bad_inputs_and_unknown_artifact(mod):
    bd = mod.Backdoor()
    with pytest.raises(mod.UnknownArtifactError):
        bd.detect("nope", 1)  # untested artifact refused fail-closed
    bd.test("art-1", 2)
    with pytest.raises(mod.BadTechniqueError):
        bd.detect("art-1", 3, technique="vibes")
    with pytest.raises(mod.BadFindingError):
        bd.detect("art-1", 4, finding="definitely-hacked")
    with pytest.raises(mod.BadDigestError):
        bd.detect("art-1", 5, evidence_digest="raw")
    with pytest.raises(mod.BadIdError):
        bd.detect("", 6)
    rejected = [r for r in bd.audit_log(7) if r["kind"] == "rejected"]
    assert len(rejected) == 5
    # all techniques accepted
    for i, tech in enumerate(mod.DETECT_TECHNIQUES):
        rec = bd.detect("art-1", 8 + i, technique=tech)
        assert rec.technique == tech
        assert rec.verify()


# 8 --------------------------------------------------------------------------
def test_mitigate_roundtrip_and_strategies(mod):
    bd = mod.Backdoor()
    bd.test("art-1", 1)
    for i, strategy in enumerate(mod.MITIGATE_STRATEGIES):
        det = bd.detect("art-1", 2 * i + 2, finding="suspect")
        rec = bd.mitigate(
            det.detection_id, 2 * i + 3, strategy=strategy,
            plan_digest=_pin(f"p{i}"),
        )
        assert rec.mitigation_id == f"mit-{i + 1}"
        assert rec.strategy == strategy
        assert rec.verify()
    # frozen
    with pytest.raises(Exception):
        rec.strategy = "remove"  # type: ignore


# 9 --------------------------------------------------------------------------
def test_mitigate_refusals(mod):
    bd = mod.Backdoor()
    bd.test("art-1", 1)
    with pytest.raises(mod.UnknownDetectionError):
        bd.mitigate("det-99", 2)
    with pytest.raises(mod.BadIdError):
        bd.mitigate("", 3)
    clean_det = bd.detect("art-1", 4, finding="clean")
    with pytest.raises(mod.MitigationNotNeededError):
        bd.mitigate(clean_det.detection_id, 5)  # clean: nothing to mitigate
    sus = bd.detect("art-1", 6, finding="confirmed")
    bd.mitigate(sus.detection_id, 7)
    with pytest.raises(mod.AlreadyMitigatedError):
        bd.mitigate(sus.detection_id, 8)  # double mitigation refused
    # bad strategy refused (state checks fire first for a fresh detection)
    other = bd.detect("art-1", 9, finding="suspect")
    with pytest.raises(mod.BadStrategyError):
        bd.mitigate(other.detection_id, 10, strategy="hopes-and-prayers")
    rejected = [r for r in bd.audit_log(11) if r["kind"] == "rejected"]
    assert len(rejected) == 5


# 10 -------------------------------------------------------------------------
def test_status_posture_math(mod):
    bd = mod.Backdoor()
    bd.test("art-1", 1)
    # tested, no detections yet -> clean
    s = bd.status("art-1", 2)
    assert s.verify()
    assert s.posture == "clean"
    assert (s.n_tests, s.n_detections, s.n_mitigations) == (1, 0, 0)
    # one suspect detection -> suspect
    d1 = bd.detect("art-1", 3, finding="suspect")
    assert bd.status("art-1", 4).posture == "suspect"
    # a confirmed detection dominates -> confirmed
    bd.detect("art-1", 5, finding="confirmed")
    assert bd.status("art-1", 6).posture == "confirmed"
    # mitigating only the suspect leaves the confirmed open
    bd.mitigate(d1.detection_id, 7)
    assert bd.status("art-1", 8).posture == "confirmed"
    # mitigate everything non-clean -> mitigated
    d3 = bd.detect("art-1", 9, finding="confirmed")
    bd.mitigate(d3.detection_id, 10)
    bd.mitigate("det-2", 11)
    assert bd.status("art-1", 12).posture == "mitigated"
    # read purity: same-seq reads, no audit rows
    rows = len(bd.audit_log(13))
    bd.status("art-1", 14)
    bd.status("art-1", 14)
    assert len(bd.audit_log(15)) == rows
    # unknown artifact refused
    with pytest.raises(mod.UnknownArtifactError):
        bd.status("nope", 16)


# 11 -------------------------------------------------------------------------
def test_seq_discipline(mod):
    bd = mod.Backdoor()
    bd.test("art-1", 1)
    rows = len(bd.audit_log(2))
    # rewind raises bare: no seq consumed, no rejected row
    with pytest.raises(mod.SeqOrderError):
        bd.test("art-2", 1)
    assert len(bd.audit_log(2)) == rows
    # malformed seqs raise bare
    for bad in (True, "2", None, -1, 0):
        with pytest.raises(mod.SeqOrderError):
            bd.test("art-2", bad)
    assert len(bd.audit_log(3)) == rows
    # failed mutation consumes its seq
    with pytest.raises(mod.BadKindError):
        bd.test("art-2", 4, trigger_kind="laser")
    with pytest.raises(mod.SeqOrderError):
        bd.test("art-2", 4)
    rec = bd.test("art-2", 5)
    assert rec.verify()
    # reads never consume
    bd.test_record("art-1", 6)
    bd.test_record("art-1", 6)


# 12 -------------------------------------------------------------------------
def test_audit_shapes_leak_ban_and_bad_kind(mod):
    bd = mod.Backdoor()
    bd.test("art-1", 1, trigger_kind="input-trigger", outcome="suspect")
    d = bd.detect("art-1", 2, technique="static-scan", finding="suspect")
    bd.mitigate(d.detection_id, 3, strategy="remove")
    kinds = [r["kind"] for r in bd.audit_log(4)]
    assert kinds == ["tested", "detected", "mitigated"]
    for row in bd.audit_log(4):
        assert row["schema"] == "audit.ndjson/1"
    # banned raw keys refused at the builder level
    with pytest.raises(mod.AuditKindError):
        mod.backdoor_audit_event("tested", 1, trigger="TRIGGER-PHRASE")
    with pytest.raises(mod.AuditKindError):
        mod.backdoor_audit_event("detected", 1, payload="raw bytes")
    with pytest.raises(mod.AuditKindError):
        mod.backdoor_audit_event("mitigated", 1, backdoor="implant desc")
    with pytest.raises(mod.AuditKindError):
        mod.backdoor_audit_event("nope", 1)
    with pytest.raises(mod.SeqOrderError):
        mod.backdoor_audit_event("tested", -1)
    # no raw content anywhere in the audit log
    blob = json.dumps(bd.audit_log(5))
    assert "TRIGGER-PHRASE" not in blob
    # rejected rows carry rejected_kind, never the raw detail
    with pytest.raises(mod.BadKindError):
        bd.test("art-2", 6, trigger_kind="laser")
    rej = [r for r in bd.audit_log(7) if r["kind"] == "rejected"]
    assert rej and rej[0]["details"]["rejected_kind"] == "test"


# 13 -------------------------------------------------------------------------
def test_cross_instance_determinism_and_tamper(mod):
    pin = _pin("artifact")
    a = mod.Backdoor()
    b = mod.Backdoor()
    ra = a.test("art-1", 1, artifact_digest=pin, outcome="suspect")
    rb = b.test("art-1", 1, artifact_digest=pin, outcome="suspect")
    assert ra.digest == rb.digest
    da = a.detect("art-1", 2, technique="red-team", finding="confirmed")
    db = b.detect("art-1", 2, technique="red-team", finding="confirmed")
    assert da.digest == db.digest
    ma = a.mitigate(da.detection_id, 3, strategy="retrain")
    mb = b.mitigate(db.detection_id, 3, strategy="retrain")
    assert ma.digest == mb.digest
    sa = a.status("art-1", 4)
    sb = b.status("art-1", 4)
    assert sa.digest == sb.digest
    # tampering breaks verify() as data
    object.__setattr__(ra, "outcome", "clean")
    assert not ra.verify()
    object.__setattr__(sa, "posture", "clean")
    assert not sa.verify()


# 14 -------------------------------------------------------------------------
def test_views_stats_and_unknown_lookups(mod):
    bd = mod.Backdoor()
    bd.test("art-1", 1)
    bd.test("art-2", 2)
    d = bd.detect("art-1", 3, finding="suspect")
    m = bd.mitigate(d.detection_id, 4)
    assert bd.artifact_ids(5) == ("art-1", "art-2")
    assert len(bd.tests_for("art-1", 6)) == 1
    assert bd.test_record("art-1", 7).artifact_id == "art-1"
    assert bd.detection_record(d.detection_id, 8).finding == "suspect"
    assert bd.mitigation_record(m.mitigation_id, 9).strategy == "remove"
    assert bd.stats(10) == {
        "artifacts": 2,
        "tests": 2,
        "detections": 1,
        "mitigations": 1,
    }
    with pytest.raises(mod.UnknownArtifactError):
        bd.test_record("nope", 11)
    with pytest.raises(mod.UnknownArtifactError):
        bd.tests_for("nope", 12)
    with pytest.raises(mod.UnknownArtifactError):
        bd.detections_for("nope", 13)
    with pytest.raises(mod.UnknownDetectionError):
        bd.detection_record("det-99", 14)
    with pytest.raises(mod.UnknownDetectionError):
        bd.mitigation_record("mit-99", 15)


# 15 -------------------------------------------------------------------------
def test_main_subprocess_and_thread_smoke(mod):
    out = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    assert "backdoor OK" in out.stdout
    # concurrent reads are safe
    bd = mod.Backdoor()
    bd.test("art-1", 1)
    bd.detect("art-1", 2, finding="suspect")
    errors = []

    def reader():
        try:
            for _ in range(50):
                bd.status("art-1", 3)
                bd.stats(3)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
