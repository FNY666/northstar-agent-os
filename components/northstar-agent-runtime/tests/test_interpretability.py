"""Tests for interpretability: model-explanation decision ledger."""

import ast
import subprocess
import sys

import pytest

import interpretability as it
from interpretability import Interpretability


def _module_path():
    return it.__file__


# ---------------------------------------------------------------------------
# pins & stdlib-only
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert it.INTERPRETABILITY_VERSION == "interpretability.v1"
    assert it.INTERPRETABILITY_SCHEMA == "northstar.interpretability.v1"
    assert it.AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only():
    tree = ast.parse(open(_module_path(), encoding="utf-8").read())
    allowed = {
        "hashlib", "math", "threading", "dataclasses", "typing",
        "__future__", "canonical_json", "json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# ---------------------------------------------------------------------------
# register_prediction
# ---------------------------------------------------------------------------


def test_register_prediction_roundtrip_and_digest():
    i = Interpretability()
    rec = i.register_prediction("pred-1", "model-x", 1,
                                input_digest="in-1", output_digest="out-1")
    assert rec.prediction_id == "pred-1"
    assert rec.model_id == "model-x"
    assert rec.seq == 1
    assert rec.digest.startswith("sha256:")
    assert rec.verify("pred-1", "model-x")
    assert not rec.verify("pred-1", "model-y")
    assert i.prediction("pred-1", 2) == rec
    assert i.prediction("nope", 3) is None
    assert i.prediction_ids(4) == ("pred-1",)


def test_register_prediction_duplicate_and_bad_inputs_consume_seq():
    i = Interpretability()
    i.register_prediction("p1", "m1", 1)
    with pytest.raises(it.DuplicatePredictionError):
        i.register_prediction("p1", "m1", 2)
    with pytest.raises(it.BadPredictionError):
        i.register_prediction("", "m1", 3)
    with pytest.raises(it.BadPredictionError):
        i.register_prediction("has space", "m1", 4)
    with pytest.raises(it.BadPredictionError):
        i.register_prediction("x" * 257, "m1", 5)
    with pytest.raises(it.BadPredictionError):
        i.register_prediction(123, "m1", 6)
    rejected = [r for r in i.audit_log() if r["kind"] == it.KIND_REJECTED]
    assert len(rejected) == 5
    assert i.prediction_ids(7) == ("p1",)


# ---------------------------------------------------------------------------
# explain
# ---------------------------------------------------------------------------


def test_explain_roundtrip_all_methods():
    i = Interpretability()
    i.register_prediction("pred-1", "model-x", 1)
    pids = []
    for idx, method in enumerate(it.METHODS, start=0):
        pid = f"pred-m-{idx}"
        i.register_prediction(pid, "model-x", 10 + idx)
        pids.append((pid, method))
    for j, (pid, method) in enumerate(pids):
        exp = i.explain(pid, 20 + j, method=method)
        assert exp.prediction_id == pid
        assert exp.method == method
        assert exp.digest.startswith("sha256:")
        assert exp.verify(pid, method)
        assert not exp.verify(pid, "shap" if method != "shap" else "lime")
    assert i.stats(99)["explanations"] == 6
    assert i.explanation_for("pred-1", 99) is None  # pred-1 never explained


def test_explain_bad_inputs_and_double_explain():
    i = Interpretability()
    with pytest.raises(it.UnknownPredictionError):
        i.explain("ghost", 1, method="shap")
    i.register_prediction("pred-1", "model-x", 2)
    with pytest.raises(it.BadMethodError):
        i.explain("pred-1", 3, method="gradcam")
    exp = i.explain("pred-1", 4, method="lime")
    assert exp.explanation_id == "exp-1"
    with pytest.raises(it.DuplicateExplanationError):
        i.explain("pred-1", 5, method="shap")
    rejected = [r for r in i.audit_log() if r["kind"] == it.KIND_REJECTED]
    assert len(rejected) == 3
    assert i.explanation_for("pred-1", 6) == "exp-1"


# ---------------------------------------------------------------------------
# attribute
# ---------------------------------------------------------------------------


def test_attribute_roundtrip_and_scores():
    i = Interpretability()
    i.register_prediction("pred-1", "model-x", 1)
    i.explain("pred-1", 2, method="shap")
    attr = i.attribute("exp-1", {"age": 0.5, "income": -0.25, "zip": 3}, 3)
    assert attr.explanation_id == "exp-1"
    assert attr.feature_count == 3
    assert attr.scores_digest.startswith("sha256:")
    assert attr.verify("exp-1", attr.scores_digest)
    scores = dict(i.attribution_scores("exp-1", 4))
    assert scores == {"age": 0.5, "income": -0.25, "zip": 3.0}
    assert i.attribution("exp-1", 5) == attr


def test_attribute_bad_inputs_consume_seq():
    i = Interpretability()
    i.register_prediction("pred-1", "model-x", 1)
    i.explain("pred-1", 2, method="lime")
    with pytest.raises(it.UnknownExplanationError):
        i.attribute("exp-9", {"a": 1.0}, 3)
    with pytest.raises(it.BadAttributionError):
        i.attribute("exp-1", {}, 4)
    with pytest.raises(it.BadAttributionError):
        i.attribute("exp-1", {"a": float("nan")}, 5)
    with pytest.raises(it.BadAttributionError):
        i.attribute("exp-1", {"a": float("inf")}, 6)
    with pytest.raises(it.BadAttributionError):
        i.attribute("exp-1", {"a": True}, 7)
    with pytest.raises(it.BadAttributionError):
        i.attribute("exp-1", {"a": 0.0, "b": 0.0}, 8)
    with pytest.raises(it.BadAttributionError):
        i.attribute("exp-1", {1: 0.5}, 9)
    with pytest.raises(it.BadAttributionError):
        i.attribute("exp-1", {"a": 1e7}, 10)
    with pytest.raises(it.BadAttributionError):
        i.attribute("exp-1", "not-a-mapping", 11)
    # one good booking, then re-booking refused
    i.attribute("exp-1", {"a": 0.5}, 12)
    with pytest.raises(it.DuplicateAttributionError):
        i.attribute("exp-1", {"a": 0.5}, 13)
    rejected = [r for r in i.audit_log() if r["kind"] == it.KIND_REJECTED]
    assert len(rejected) == 10


# ---------------------------------------------------------------------------
# visualize
# ---------------------------------------------------------------------------


def test_visualize_roundtrip_all_kinds():
    i = Interpretability()
    i.register_prediction("pred-1", "model-x", 1)
    i.explain("pred-1", 2, method="attention")
    for idx, kind in enumerate(it.VIS_KINDS, start=3):
        vis = i.visualize("exp-1", idx, kind=kind)
        assert vis.visualization_id == f"vis-{idx - 2}"
        assert vis.kind == kind
        assert vis.verify("exp-1", kind)
        assert not vis.verify("exp-1", "bar" if kind != "bar" else "text")
    assert i.visualization("vis-1", 99) is not None
    assert i.visualization("vis-9", 99) is None


def test_visualize_bad_inputs_consume_seq():
    i = Interpretability()
    with pytest.raises(it.UnknownExplanationError):
        i.visualize("exp-1", 1, kind="bar")
    i.register_prediction("pred-1", "model-x", 2)
    i.explain("pred-1", 3, method="shap")
    with pytest.raises(it.BadVisualizationError):
        i.visualize("exp-1", 4, kind="3d-scatter")
    rejected = [r for r in i.audit_log() if r["kind"] == it.KIND_REJECTED]
    assert len(rejected) == 2


# ---------------------------------------------------------------------------
# seq discipline & view purity
# ---------------------------------------------------------------------------


def test_seq_ordering_rewind_and_malformed():
    i = Interpretability()
    i.register_prediction("pred-1", "model-x", 5)
    with pytest.raises(it.SeqOrderError):
        i.register_prediction("pred-2", "model-x", 5)
    with pytest.raises(it.SeqOrderError):
        i.register_prediction("pred-2", "model-x", 4)
    for bad in (True, "x", 1.5, None):
        with pytest.raises(it.SeqOrderError):
            i.register_prediction("pred-2", "model-x", bad)
    # rewinds consume nothing: next valid seq is still 6
    i.register_prediction("pred-2", "model-x", 6)
    assert i.prediction_ids(7) == ("pred-1", "pred-2")


def test_views_are_pure_reads():
    i = Interpretability()
    i.register_prediction("pred-1", "model-x", 1)
    i.explain("pred-1", 2, method="shap")
    audit_before = len(i.audit_log())
    i.stats(2)
    i.explanation_ids(2)
    i.attribution("exp-1", 2)
    i.attribution_scores("exp-1", 2)
    assert len(i.audit_log()) == audit_before
    with pytest.raises(it.SeqOrderError):
        i.stats("x")


# ---------------------------------------------------------------------------
# audit, determinism, concurrency, main
# ---------------------------------------------------------------------------


def test_audit_shapes_and_leak_ban_and_bad_kind():
    i = Interpretability()
    i.register_prediction("pred-1", "model-x", 1)
    i.explain("pred-1", 2, method="shap")
    i.attribute("exp-1", {"secret-feature": 0.9}, 3)
    i.visualize("exp-1", 4, kind="bar")
    rows = i.audit_log()
    assert [r["kind"] for r in rows] == [
        it.KIND_PREDICTION_REGISTERED, it.KIND_EXPLANATION_BOOKED,
        it.KIND_ATTRIBUTED, it.KIND_VISUALIZED]
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        joined = str(r["detail"])
        assert "secret-feature" not in joined
        assert "0.9" not in joined
    with pytest.raises(it.AuditKindError):
        it.interpretability_audit_event("bogus", 1)
    with pytest.raises(it.AuditKindError):
        it.interpretability_audit_event(it.KIND_ATTRIBUTED, 1,
                                        attributions={"a": 1.0})
    with pytest.raises(it.AuditKindError):
        it.interpretability_audit_event(it.KIND_EXPLANATION_BOOKED, 1,
                                        summary="secret text")


def test_cross_instance_digest_determinism():
    def build():
        i = Interpretability()
        i.register_prediction("pred-1", "model-x", 1)
        e = i.explain("pred-1", 2, method="integrated-gradients")
        a = i.attribute("exp-1", {"f1": 0.1, "f2": -0.2}, 3)
        v = i.visualize("exp-1", 4, kind="force")
        return e.digest, a.digest, a.scores_digest, v.digest
    assert build() == build()


def test_concurrency_smoke():
    import threading
    i = Interpretability()
    i.register_prediction("pred-1", "model-x", 1)
    i.explain("pred-1", 2, method="lime")
    i.attribute("exp-1", {"a": 0.5}, 3)
    errors = []

    def reader():
        try:
            for _ in range(200):
                i.stats(999)
                i.prediction_ids(999)
                i.explanation_ids(999)
                i.attribution_scores("exp-1", 999)
                i.attribution("exp-1", 999)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert i.stats(1000)["audit_rows"] == 3


def test_main_subprocess():
    result = subprocess.run(
        [sys.executable, _module_path()],
        capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert "interpretability OK" in result.stdout
