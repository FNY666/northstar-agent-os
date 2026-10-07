"""Tests for robustness_testing.py (15 tests)."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import robustness_testing as rt
from robustness_testing import (
    ROBUSTNESS_TESTING_VERSION,
    ROBUSTNESS_TESTING_SCHEMA,
    AUDIT_SCHEMA,
    RobustnessTesting,
    apply_perturbation,
    robustness_testing_audit_event,
    RobustnessTestingError,
    BadOpError,
    BadTargetError,
    DuplicateTargetError,
    UnknownTargetError,
    BadMagnitudeError,
    BadMappingError,
    UnknownPerturbationError,
    BadScoreError,
    NoTrialsError,
    SeqOrderError,
    AuditKindError,
)

HERE = Path(__file__).resolve()
MOD = HERE.parent.parent / "robustness_testing.py"


def fresh():
    return RobustnessTesting()


def test_version_and_schema_pins():
    assert ROBUSTNESS_TESTING_VERSION == "robustness-testing.v1"
    assert ROBUSTNESS_TESTING_SCHEMA == "northstar.robustness-testing.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"
    assert rt.KIND_TARGET_REGISTERED == "target-registered"
    assert rt.KIND_PERTURBED == "perturbed"
    assert rt.KIND_STRESSED == "stressed"
    assert rt.KIND_SCORED == "scored"
    assert rt.KIND_REJECTED == "rejected"


def test_stdlib_only_ast():
    tree = ast.parse(MOD.read_text())
    allowed = {"hashlib", "math", "threading", "dataclasses", "typing",
               "__future__", "canonical_json", "json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_target_roundtrip_verify_frozen():
    r = fresh()
    rec = r.target("model-a", 1)
    assert rec.target_id == "model-a" and rec.seq == 1
    assert rec.digest.startswith("sha256:")
    assert rec.verify("model-a")
    assert not rec.verify("model-b")
    with pytest.raises(Exception):
        rec.target_id = "x"  # frozen


def test_duplicate_target_seq_burn_and_rejected_row():
    r = fresh()
    r.target("model-a", 1)
    with pytest.raises(DuplicateTargetError):
        r.target("model-a", 2)
    # Failed mutation consumed its seq: next mutation needs seq 3.
    with pytest.raises(SeqOrderError):
        r.target("model-b", 2)
    r.target("model-b", 3)
    kinds = [row["kind"] for row in r.audit_log()]
    assert kinds.count("target-registered") == 2
    assert kinds.count("rejected") == 1
    rejected = [row for row in r.audit_log() if row["kind"] == "rejected"]
    assert rejected[0]["detail"]["error"] == "DuplicateTargetError"


def test_perturb_roundtrip_op_vocabulary_verify():
    r = fresh()
    r.target("t", 1)
    seq = 2
    for op in ("typo", "synonym", "truncate", "shuffle", "noise", "case"):
        kw = {}
        if op == "synonym":
            kw["mapping"] = {"good": "great"}
        rec = r.perturb("t", op, seq, magnitude=0.3, **kw)
        assert rec.op == op and rec.verify("t", op, 0.3)
        assert rec.pert_id == f"pert-{seq - 1}"
        seq += 1
    assert r.perturbation_ids() == tuple(f"pert-{i}" for i in range(1, 7))


def test_perturb_bad_inputs_seq_burn():
    r = fresh()
    r.target("t", 1)
    bad = [
        (("t", "nope", 2), {}, BadOpError),                    # unknown op
        (("t", 123, 3), {}, BadOpError),                       # non-str op
        (("t", "typo", 4), {"magnitude": 0.0}, BadMagnitudeError),  # zero
        (("t", "typo", 5), {"magnitude": 1.5}, BadMagnitudeError),   # > 1
        (("t", "typo", 6), {"magnitude": float("nan")}, BadMagnitudeError),
        (("t", "typo", 7), {"magnitude": True}, BadMagnitudeError), # bool
        (("t", "synonym", 8), {}, BadMappingError),           # missing map
        (("t", "synonym", 9), {"mapping": {}}, BadMappingError),  # empty map
        (("t", "typo", 10), {"mapping": {"a": "b"}}, BadMappingError),  # misplaced
        (("nope", "typo", 11), {}, UnknownTargetError),
        (("", "typo", 12), {}, BadTargetError),
    ]
    for args, kwargs, exc in bad:
        with pytest.raises(exc):
            r.perturb(*args, **kwargs)
    # Every failed mutation burned its seq: none of 2..12 are reusable.
    with pytest.raises(SeqOrderError):
        r.target("t2", 12)
    r.target("t2", 13)
    assert r.audit_log()[-1]["kind"] == "target-registered"


def test_stress_roundtrip_drop_derived_as_data():
    r = fresh()
    r.target("t", 1)
    p = r.perturb("t", "noise", 2)
    rec = r.stress(p.pert_id, 0.9, 0.7, 3)
    assert rec.trial_id == "stress-1"
    assert abs(rec.drop - 0.2) < 1e-12
    assert rec.verify("t", 0.9, 0.7)
    # Negative drop (perturbation helped) is data, never raised.
    rec2 = r.stress(p.pert_id, 0.8, 0.95, 4)
    assert abs(rec2.drop - (-0.15)) < 1e-12
    assert r.trial_ids() == ("stress-1", "stress-2")


def test_stress_bad_inputs():
    r = fresh()
    r.target("t", 1)
    p = r.perturb("t", "typo", 2)
    bad = [
        ("nope", 0.9, 0.9, 3, UnknownPerturbationError),
        (p.pert_id, 1.5, 0.9, 4, BadScoreError),   # base > 1
        (p.pert_id, -0.1, 0.9, 5, BadScoreError),  # base < 0
        (p.pert_id, 0.9, float("inf"), 6, BadScoreError),
        (p.pert_id, 0.9, float("nan"), 7, BadScoreError),
        (p.pert_id, True, 0.9, 8, BadScoreError),  # bool
        (p.pert_id, "0.9", 0.9, 9, BadScoreError), # str
    ]
    for pert_id, base, pert, seq, exc in bad:
        with pytest.raises(exc):
            r.stress(pert_id, base, pert, seq)
    # Ints 0/1 are accepted as float.
    rec = r.stress(p.pert_id, 1, 0, 10)
    assert rec.drop == 1.0


def test_score_aggregate_verdict_and_verify():
    r = fresh()
    r.target("t", 1)
    p1 = r.perturb("t", "typo", 2)
    p2 = r.perturb("t", "shuffle", 3)
    r.stress(p1.pert_id, 0.9, 0.7, 4)    # drop 0.2
    r.stress(p1.pert_id, 0.9, 0.6, 5)    # drop 0.3
    r.stress(p2.pert_id, 1.0, 0.95, 6)   # drop 0.05
    rep = r.score("t", 7)
    assert rep.trials == 3
    assert abs(rep.mean_drop - (0.2 + 0.3 + 0.05) / 3) < 1e-12
    assert abs(rep.worst_drop - 0.3) < 1e-12
    assert abs(rep.best_drop - 0.05) < 1e-12
    assert abs(rep.robustness - (1.0 - rep.mean_drop)) < 1e-12
    # 1 - 0.1833 = 0.8167 -> borderline.
    assert rep.verdict == "borderline"
    assert rep.verify("t", 3, rep.mean_drop)
    ops = {o.op: o for o in rep.per_op}
    assert set(ops) == {"typo", "shuffle"}
    assert ops["typo"].trials == 2
    assert abs(ops["typo"].mean_drop - 0.25) < 1e-12
    assert r.audit_log()[-1]["kind"] == "scored"


def test_score_verdict_boundaries_and_no_trials():
    r = fresh()
    r.target("clean", 1)
    p = r.perturb("clean", "case", 2)
    r.stress(p.pert_id, 1.0, 1.0, 3)  # drop 0 -> robustness 1.0
    assert r.score("clean", 4).verdict == "robust"
    r.target("fragile", 5)
    q = r.perturb("fragile", "truncate", 6)
    r.stress(q.pert_id, 1.0, 0.5, 7)  # drop 0.5 -> robustness 0.5
    assert r.score("fragile", 8).verdict == "fragile"
    r.target("empty", 9)
    with pytest.raises(NoTrialsError):
        r.score("empty", 10)
    with pytest.raises(UnknownTargetError):
        r.score("ghost", 11)


def test_seq_discipline_rewind_bare_malformed():
    r = fresh()
    r.target("t", 1)
    # Rewind raises bare, consumes nothing: seq 1 still the last.
    with pytest.raises(SeqOrderError):
        r.target("u", 1)
    r.target("u", 2)
    for bad in (True, "3", 2.5, None, -1):
        with pytest.raises(SeqOrderError):
            r.perturb("t", "typo", bad)
    # Pure views validate seq shape but never consume.
    assert r.stats(2) == {"targets": 2, "perturbations": 0, "trials": 0}
    assert r.stats(2) == {"targets": 2, "perturbations": 0, "trials": 0}
    trials = r.trials("t", 2)
    assert trials == ()
    with pytest.raises(SeqOrderError):
        r.trials("t", "2")


def test_audit_shapes_leak_ban_and_bad_kind():
    r = fresh()
    r.target("t", 1)
    p = r.perturb("t", "typo", 2, magnitude=0.2)
    r.stress(p.pert_id, 0.9, 0.8, 3)
    r.score("t", 4)
    rows = r.audit_log()
    assert [row["kind"] for row in rows] == [
        "target-registered", "perturbed", "stressed", "scored"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == "robustness-testing.v1"
        assert row["seq"] in (1, 2, 3, 4)
    blob = str(rows)
    assert "0.9" not in blob and "0.8" not in blob
    with pytest.raises(AuditKindError):
        robustness_testing_audit_event("nope", {}, 5)
    with pytest.raises(AuditKindError):
        robustness_testing_audit_event("stressed", {"base": 0.9}, 5)
    with pytest.raises(AuditKindError):
        robustness_testing_audit_event("scored", {"mapping": {"a": "b"}}, 5)


def test_recipe_deterministic_and_semantics():
    text = "the quick brown fox jumps over the lazy dog"
    for op in ("typo", "truncate", "shuffle", "noise", "case"):
        a = apply_perturbation(text, op, 0.3)
        b = apply_perturbation(text, op, 0.3)
        assert a == b  # deterministic
    # truncate shortens; shuffle preserves the word multiset.
    trunc = apply_perturbation(text, "truncate", 0.5)
    assert len(trunc) < len(text) and text.startswith(trunc)
    shuf = apply_perturbation(text, "shuffle", 0.5)
    assert sorted(shuf.split()) == sorted(text.split())
    # synonym applies the host mapping verbatim.
    syn = apply_perturbation("a b c", "synonym", 0.5,
                             {"b": "BEE"})
    assert syn == "a BEE c"
    with pytest.raises(BadOpError):
        apply_perturbation(text, "nope", 0.3)
    with pytest.raises(BadMagnitudeError):
        apply_perturbation(text, "typo", 0.0)
    with pytest.raises(BadMappingError):
        apply_perturbation("a b", "synonym", 0.5)


def test_cross_instance_digest_determinism():
    a, b = fresh(), fresh()
    ra = a.target("t", 1)
    rb = b.target("t", 1)
    assert ra.digest == rb.digest
    pa = a.perturb("t", "typo", 2, magnitude=0.2)
    pb = b.perturb("t", "typo", 2, magnitude=0.2)
    assert pa.digest == pb.digest
    sa = a.stress(pa.pert_id, 0.9, 0.7, 3)
    sb = b.stress(pb.pert_id, 0.9, 0.7, 3)
    assert sa.digest == sb.digest
    qa = a.score("t", 4)
    qb = b.score("t", 4)
    assert qa.digest == qb.digest


def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MOD)], capture_output=True, text=True,
        timeout=60, cwd=str(MOD.parent))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "robustness-testing OK: target, perturb, stress, score, recipe")
