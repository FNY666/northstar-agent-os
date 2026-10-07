"""Tests for the data-extraction attack/defense decision ledger, Simulated."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "data_extraction.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("data_extraction", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["data_extraction"] = module
    spec.loader.exec_module(module)
    return module


data_extraction = _load()


# 1. version/schema pins + vocabulary
def test_version_and_schema_pins():
    assert data_extraction.DATA_EXTRACTION_VERSION == "data-extraction.v1"
    assert data_extraction.SCHEMA_PIN == "northstar.data-extraction.v1"
    assert data_extraction.ATTACKS == (
        "canary-injection",
        "membership-inference",
        "model-inversion",
        "training-extraction",
        "paraphrase-probing",
        "prompt-extraction",
    )
    assert data_extraction.TEST_OUTCOMES == (
        "extracted",
        "not-extracted",
        "inconclusive",
    )
    assert data_extraction.DEFENSES == (
        "output-perturbation",
        "query-throttling",
        "canary-marking",
        "deduplication",
        "differential-privacy",
        "response-filtering",
    )
    assert data_extraction.RESIDUAL_RISK_LEVELS == (
        "unknown",
        "elevated",
        "contained",
    )
    assert data_extraction.AUDIT_KINDS == ("tested", "defended", "rejected")


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
    }
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= allowed, imports - allowed


# 3. test roundtrip + verify + implicit target registration
def test_test_roundtrip():
    d = data_extraction.DataExtraction()
    rec = d.test("tgt-1", "membership-inference", 1, outcome="extracted",
                 evidence_digest=PIN)
    assert rec.test_id == "tst-1"
    assert rec.target_id == "tgt-1"
    assert rec.attack == "membership-inference"
    assert rec.outcome == "extracted"
    assert rec.evidence_digest == PIN
    assert rec.verify()
    assert rec.as_dict()["schema"] == data_extraction.SCHEMA_PIN
    # first test implicitly registered the target
    assert d.target_ids(0) == ("tgt-1",)
    assert d.tests_for("tgt-1", 0) == ("tst-1",)
    got = d.test_record("tst-1", 0)
    assert got.verify()
    # default outcome + zero-pin default digest
    rec2 = d.test("tgt-1", "canary-injection", 2)
    assert rec2.outcome == "inconclusive"
    assert rec2.evidence_digest == "sha256:" + "00" * 32
    assert rec2.verify()
    assert rec2.test_id == "tst-2"


# 4. test bad-input table + seq-burn + rejected rows
def test_test_refusals():
    d = data_extraction.DataExtraction()
    seq = 0
    rejected = 0
    with pytest.raises(data_extraction.BadAttackError):
        seq += 1
        d.test("tgt-1", "shoulder-surfing", seq)
    rejected += 1
    with pytest.raises(data_extraction.BadOutcomeError):
        seq += 1
        d.test("tgt-1", "membership-inference", seq, outcome="maybe")
    rejected += 1
    with pytest.raises(data_extraction.BadDigestError):
        seq += 1
        d.test("tgt-1", "membership-inference", seq, evidence_digest="not-a-pin")
    rejected += 1
    with pytest.raises(data_extraction.BadDigestError):
        seq += 1
        d.test("tgt-1", "membership-inference", seq, evidence_digest="sha256:zzz")
    rejected += 1
    with pytest.raises(data_extraction.BadTargetError):
        seq += 1
        d.test("", "membership-inference", seq)
    rejected += 1
    with pytest.raises(data_extraction.BadTargetError):
        seq += 1
        d.test(None, "membership-inference", seq)
    rejected += 1
    rows = d.audit_log(0)
    rej_rows = [r for r in rows if r["kind"] == "rejected"]
    assert len(rej_rows) == rejected
    assert d.stats(0)["tests"] == 0
    assert d.stats(0)["targets"] == 0


# 5. full attack vocabulary acceptance
def test_all_attacks():
    d = data_extraction.DataExtraction()
    seq = 0
    for i, attack in enumerate(data_extraction.ATTACKS):
        seq += 1
        r = d.test("tgt-a", attack, seq, outcome="not-extracted")
        assert r.attack == attack and r.verify()
        assert r.test_id == f"tst-{i + 1}"
    assert d.stats(0)["tests"] == len(data_extraction.ATTACKS)


# 6. defend roundtrip + minted ids + verify
def test_defend_roundtrip():
    d = data_extraction.DataExtraction()
    d.test("tgt-1", "membership-inference", 1)
    d1 = d.defend("tgt-1", "output-perturbation", 2, plan_digest=PIN)
    assert d1.defense_id == "def-1"
    assert d1.target_id == "tgt-1"
    assert d1.defense == "output-perturbation"
    assert d1.plan_digest == PIN
    assert d1.verify()
    assert d1.as_dict()["schema"] == data_extraction.SCHEMA_PIN
    d2 = d.defend("tgt-1", "differential-privacy", 3)
    assert d2.defense_id == "def-2"
    assert d2.plan_digest == "sha256:" + "00" * 32
    assert d2.verify()
    assert d.defenses_for("tgt-1", 0) == ("def-1", "def-2")
    assert d.defense_record("def-1", 0).verify()


# 7. defend refusals: unknown target, bad defense, bad digest
def test_defend_refusals():
    d = data_extraction.DataExtraction()
    d.test("tgt-1", "membership-inference", 1)
    seq = 1
    rejected = 0
    with pytest.raises(data_extraction.UnknownTargetError):
        seq += 1
        d.defend("ghost", "output-perturbation", seq)
    rejected += 1
    with pytest.raises(data_extraction.BadDefenseError):
        seq += 1
        d.defend("tgt-1", "panic-button", seq)
    rejected += 1
    with pytest.raises(data_extraction.BadDigestError):
        seq += 1
        d.defend("tgt-1", "output-perturbation", seq, plan_digest="nope")
    rejected += 1
    with pytest.raises(data_extraction.BadTargetError):
        seq += 1
        d.defend("", "output-perturbation", seq)
    rejected += 1
    rej_rows = [r for r in d.audit_log(0) if r["kind"] == "rejected"]
    assert len(rej_rows) == rejected
    assert d.stats(0)["defenses"] == 0


# 8. full defense vocabulary acceptance
def test_all_defenses():
    d = data_extraction.DataExtraction()
    d.test("tgt-d", "training-extraction", 1)
    seq = 1
    for i, defense in enumerate(data_extraction.DEFENSES):
        seq += 1
        r = d.defend("tgt-d", defense, seq)
        assert r.defense == defense and r.verify()
        assert r.defense_id == f"def-{i + 1}"
    assert d.stats(0)["defenses"] == len(data_extraction.DEFENSES)


# 9. evaluate posture math: contained / elevated / recovery / unknown-target
def test_evaluate():
    d = data_extraction.DataExtraction()
    d.test("tgt-1", "membership-inference", 1, outcome="not-extracted")
    r = d.evaluate("tgt-1", 0)
    assert r.verify()
    assert r.n_tests == 1 and r.n_extracted == 0 and r.n_defenses == 0
    assert r.residual_risk == "contained"
    assert r.integrity_ok
    # extracted with no defense -> elevated
    d.test("tgt-1", "training-extraction", 2, outcome="extracted")
    r = d.evaluate("tgt-1", 0)
    assert r.residual_risk == "elevated"
    assert r.n_extracted == 1
    # defense booked after the extraction -> contained
    d.defend("tgt-1", "deduplication", 3)
    r = d.evaluate("tgt-1", 0)
    assert r.residual_risk == "contained"
    assert r.n_defenses == 1
    # fresh extracted test after the defense -> elevated again
    d.test("tgt-1", "canary-injection", 4, outcome="extracted")
    r = d.evaluate("tgt-1", 0)
    assert r.residual_risk == "elevated"
    assert r.n_extracted == 2 and r.n_tests == 3
    # inconclusive does not move the needle alone
    d2 = data_extraction.DataExtraction()
    d2.test("tgt-9", "prompt-extraction", 1)
    r9 = d2.evaluate("tgt-9", 0)
    assert r9.residual_risk == "contained"
    with pytest.raises(data_extraction.UnknownTargetError):
        d.evaluate("ghost", 0)


# 10. seq discipline: rewind raises bare, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    d = data_extraction.DataExtraction()
    d.test("tgt-1", "membership-inference", 5)
    # rewind raises bare and consumes nothing
    with pytest.raises(data_extraction.SeqOrderError):
        d.test("tgt-2", "membership-inference", 5)
    with pytest.raises(data_extraction.SeqOrderError):
        d.defend("tgt-1", "output-perturbation", 4)
    assert d.stats(0)["tests"] == 1
    for bad in (True, "6", None, -1, 0):
        with pytest.raises(data_extraction.SeqOrderError):
            d.test("tgt-x", "membership-inference", bad)
    # failed mutation consumed the seq: next valid call must be higher
    with pytest.raises(data_extraction.SeqOrderError):
        d.test("tgt-3", "membership-inference", 5)
    r = d.test("tgt-3", "membership-inference", 6)
    assert r.verify()


# 11. view read-purity: same seq twice, no audit rows, nothing consumed
def test_view_read_purity():
    d = data_extraction.DataExtraction()
    d.test("tgt-1", "membership-inference", 1)
    d.defend("tgt-1", "output-perturbation", 2)
    n_rows = d.stats(0)["audit_rows"]
    for _ in range(3):
        assert d.evaluate("tgt-1", 0).verify()
        assert d.test_record("tst-1", 0).verify()
        assert d.defense_record("def-1", 0).verify()
        assert d.target_ids(0) == ("tgt-1",)
        assert d.test_ids(0) == ("tst-1",)
        assert d.defense_ids(0) == ("def-1",)
        assert d.tests_for("tgt-1", 0) == ("tst-1",)
        assert d.defenses_for("tgt-1", 0) == ("def-1",)
        assert d.stats(0) == {
            "targets": 1,
            "tests": 1,
            "defenses": 1,
            "audit_rows": n_rows,
        }
    assert d.stats(0)["audit_rows"] == n_rows
    with pytest.raises(data_extraction.UnknownTestError):
        d.test_record("tst-9", 0)
    with pytest.raises(data_extraction.UnknownDefenseError):
        d.defense_record("def-9", 0)
    with pytest.raises(data_extraction.UnknownTargetError):
        d.tests_for("ghost", 0)
    with pytest.raises(data_extraction.UnknownTargetError):
        d.defenses_for("ghost", 0)
    # view seqs are shape-checked but never consumed: seq=0 ok, negatives raise
    with pytest.raises(data_extraction.SeqOrderError):
        d.stats(-1)
    with pytest.raises(data_extraction.SeqOrderError):
        d.stats("0")


# 12. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    d = data_extraction.DataExtraction()
    d.test("tgt-1", "membership-inference", 1, outcome="extracted",
           evidence_digest=PIN)
    d.defend("tgt-1", "output-perturbation", 2, plan_digest=PIN2)
    rows = d.audit_log(0)
    kinds = [r["kind"] for r in rows]
    assert kinds == ["tested", "defended"]
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
    # audit builder: bad kind
    with pytest.raises(data_extraction.AuditKindError):
        data_extraction.data_extraction_audit_event("tested-wrong", 4)
    # audit builder: bad seq
    with pytest.raises(data_extraction.SeqOrderError):
        data_extraction.data_extraction_audit_event("tested", -1)
    # audit builder: banned raw keys
    for banned in ("training_data", "extracted_text", "canary", "response",
                   "description", "prompt"):
        with pytest.raises(data_extraction.AuditKindError):
            data_extraction.data_extraction_audit_event(
                "tested", 4, **{banned: "x"})
    # pinned vocabulary values remain emittable as declared data
    ok = data_extraction.data_extraction_audit_event(
        "tested", 4, attack="membership-inference", outcome="extracted")
    assert ok["details"]["attack"] == "membership-inference"
    # no raw keys anywhere in the audit log
    banned = data_extraction._BANNED_AUDIT_KEYS
    for r in rows:
        assert not (set(r["details"]) & banned)


# 13. cross-instance digest determinism + tamper breaks verify
def test_digest_determinism_and_tamper():
    b1, b2 = data_extraction.DataExtraction(), data_extraction.DataExtraction()
    r1 = b1.test("tgt-1", "membership-inference", 1, outcome="extracted",
                 evidence_digest=PIN)
    r2 = b2.test("tgt-1", "membership-inference", 1, outcome="extracted",
                 evidence_digest=PIN)
    assert r1.digest == r2.digest
    d1 = b1.defend("tgt-1", "output-perturbation", 2, plan_digest=PIN2)
    d2 = b2.defend("tgt-1", "output-perturbation", 2, plan_digest=PIN2)
    assert d1.digest == d2.digest
    assert d1.verify() and d2.verify()
    e1 = b1.evaluate("tgt-1", 0)
    e2 = b2.evaluate("tgt-1", 0)
    assert e1.digest == e2.digest and e1.verify() and e2.verify()
    object.__setattr__(r1, "outcome", "not-extracted")
    assert not r1.verify()
    object.__setattr__(d1, "defense", "query-throttling")
    assert not d1.verify()
    # tamper flips integrity_ok on the next evaluate (as data, not raise)
    e3 = b1.evaluate("tgt-1", 0)
    assert not e3.integrity_ok
    assert e3.verify()


# 14. frozen-ness + threaded read smoke
def test_frozen_and_threaded():
    import dataclasses

    d = data_extraction.DataExtraction()
    rec = d.test("tgt-1", "membership-inference", 1)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.outcome = "extracted"
    dfn = d.defend("tgt-1", "output-perturbation", 2)
    with pytest.raises(dataclasses.FrozenInstanceError):
        dfn.defense = "query-throttling"
    rpt = d.evaluate("tgt-1", 0)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rpt.residual_risk = "elevated"

    errors = []

    def reader():
        try:
            for _ in range(50):
                assert d.evaluate("tgt-1", 0).verify()
                assert d.target_ids(0) == ("tgt-1",)
                assert d.stats(0)["tests"] == 1
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


# 15. main() subprocess check + standalone import
def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(MOD.parent),
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "data-extraction OK: test, defend, evaluate, pins")
