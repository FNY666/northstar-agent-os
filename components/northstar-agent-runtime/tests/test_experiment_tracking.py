"""Tests for experiment_tracking: simulated W&B-style run bookkeeping."""

import ast
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from experiment_tracking import (
    AGG_LAST,
    AGG_MAX,
    AGG_MEAN,
    AGG_MIN,
    ARTIFACT_DATASET,
    ARTIFACT_LOG,
    ARTIFACT_MODEL,
    AUDIT_SCHEMA,
    BadArtifactError,
    BadCompareError,
    BadExperimentError,
    BadMetricError,
    DIR_MAX,
    DIR_MIN,
    DuplicateArtifactError,
    DuplicateExperimentError,
    EXPERIMENT_TRACKING_SCHEMA,
    EXPERIMENT_TRACKING_VERSION,
    KIND_ARTIFACT_BOUND,
    KIND_COMPARED,
    KIND_EXPERIMENT_CREATED,
    KIND_METRIC_LOGGED,
    KIND_REJECTED,
    SeqOrderError,
    UnknownExperimentError,
    ExperimentTracking,
    ExperimentTrackingError,
    experiment_tracking_audit_event,
)

MODULE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "experiment_tracking.py"
)

_STDLIB_ALLOW = {
    "hashlib",
    "hmac",
    "json",
    "threading",
    "dataclasses",
    "typing",
    "__future__",
    "canonical_json",  # standard guarded fallback across the batch line
}

_DIGEST = "sha256:" + "cd" * 32


def fresh(seed="t"):
    return ExperimentTracking(seed=seed)


def make_exp(mon, seq=0, eid="exp-1", config=None):
    return mon.create_experiment(
        eid, "run", {"lr": 0.01, "model": "mlp"} if config is None else config, seq
    )


# --- pins -----------------------------------------------------------------


def test_version_schema_pins():
    assert EXPERIMENT_TRACKING_VERSION == "experiment-tracking.v1"
    assert EXPERIMENT_TRACKING_SCHEMA == "northstar.experiment-tracking.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"
    mon = fresh()
    rec = make_exp(mon)
    assert rec.digest.startswith("sha256:")
    assert rec.verify(seed="t")
    assert not rec.verify(seed="other")


def test_stdlib_only_ast():
    tree = ast.parse(open(MODULE_PATH).read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported <= _STDLIB_ALLOW, f"non-stdlib imports: {imported - _STDLIB_ALLOW}"


# --- create_experiment ------------------------------------------------------


def test_create_roundtrip():
    mon = fresh()
    rec = make_exp(mon, seq=0)
    assert rec.experiment_id == "exp-1"
    assert dict(rec.config) == {"lr": 0.01, "model": "mlp"}
    assert mon.experiment("exp-1") is rec
    assert mon.experiment_ids() == ("exp-1",)


def test_create_duplicate():
    mon = fresh()
    make_exp(mon, seq=0)
    try:
        make_exp(mon, seq=1)
    except DuplicateExperimentError:
        pass
    else:
        raise AssertionError("expected DuplicateExperimentError")
    assert mon.stats()["last_seq"] == 1  # failed mutation consumed its seq
    assert mon.audit_log()[-1]["kind"] == KIND_REJECTED


def test_create_bad_inputs():
    mon = fresh()
    bad = [
        ("", "n", {}),
        ("e", "", {}),
        ("e", "n", "not-a-mapping"),
        ("e", "n", {"lr": float("nan")}),
        ("e", "n", {"lr": float("inf")}),
        ("e", "n", {123: "x"}),
        ("e", "n", {"lr": object()}),
        ("x" * 129, "n", {}),
    ]
    for i, (eid, name, cfg) in enumerate(bad):
        try:
            mon.create_experiment(eid, name, cfg, i)
        except ExperimentTrackingError:
            pass
        else:
            raise AssertionError(f"expected refusal for {eid!r}/{name!r}")
    assert mon.stats()["experiments"] == 0


def test_seq_ordering():
    mon = fresh()
    make_exp(mon, seq=5)
    for bad in (5, 3, -1, True, 2.5, "6"):
        try:
            mon.log("exp-1", {"loss": 0.1}, bad)
        except ExperimentTrackingError:
            pass
        else:
            raise AssertionError(f"expected seq refusal for {bad!r}")
    assert mon.stats()["metric_logs"] == 0


# --- log --------------------------------------------------------------------


def test_log_roundtrip_and_chain():
    mon = fresh()
    make_exp(mon, seq=0)
    e1 = mon.log("exp-1", {"loss": 0.5, "acc": 0.8}, 1)
    e2 = mon.log("exp-1", {"loss": 0.4}, 2)
    assert e1.log_id == "log-0" and e2.log_id == "log-1"
    assert e1.step == 0 and e2.step == 1  # auto steps
    assert e2.prev_digest == e1.digest
    assert e1.verify(seed="t") and e2.verify(seed="t")
    assert dict(e1.metrics) == {"acc": 0.8, "loss": 0.5}
    assert mon.stats()["metric_logs"] == 2


def test_log_explicit_step_and_counter():
    mon = fresh()
    make_exp(mon, seq=0)
    e = mon.log("exp-1", {"loss": 0.9}, 1, step=10)
    assert e.step == 10
    e2 = mon.log("exp-1", {"loss": 0.8}, 2)
    assert e2.step == 11  # counter advanced past explicit step


def test_log_bad_inputs():
    mon = fresh()
    make_exp(mon, seq=0)
    bad_metrics = [
        {},
        "nope",
        {"": 1.0},
        {"loss": True},
        {"loss": float("nan")},
        {"loss": float("inf")},
        {"loss": 2**60},
        {"loss": "high"},
    ]
    for i, m in enumerate(bad_metrics):
        try:
            mon.log("exp-1", m, 10 + i)
        except BadMetricError:
            pass
        else:
            raise AssertionError(f"expected BadMetricError for {m!r}")
    try:
        mon.log("exp-1", {"loss": 0.1}, 100, step=-1)
    except BadMetricError:
        pass
    else:
        raise AssertionError("expected BadMetricError for negative step")
    try:
        mon.log("nope", {"loss": 0.1}, 101)
    except UnknownExperimentError:
        pass
    else:
        raise AssertionError("expected UnknownExperimentError")
    assert mon.stats()["metric_logs"] == 0


def test_metric_value_int_coerced():
    mon = fresh()
    make_exp(mon, seq=0)
    e = mon.log("exp-1", {"epoch": 3}, 1)
    assert dict(e.metrics)["epoch"] == 3.0


# --- artifact ---------------------------------------------------------------


def test_artifact_roundtrip():
    mon = fresh()
    make_exp(mon, seq=0)
    art = mon.artifact("exp-1", "ckpt-1", ARTIFACT_MODEL, _DIGEST, 1)
    assert art.kind == ARTIFACT_MODEL
    assert art.digest_ref == _DIGEST
    assert art.verify(seed="t")
    assert mon.artifacts_for("exp-1") == (art,)


def test_artifact_bad_inputs():
    mon = fresh()
    make_exp(mon, seq=0)
    cases = [
        ("exp-1", "a", "weights", _DIGEST),  # bad kind
        ("exp-1", "a", ARTIFACT_MODEL, "md5:abc"),  # bad prefix
        ("exp-1", "a", ARTIFACT_MODEL, "sha256:xyz"),  # bad hex
        ("exp-1", "a", ARTIFACT_DATASET, "sha256:" + "zz" * 32),  # bad hex chars
        ("exp-1", "", ARTIFACT_LOG, _DIGEST),  # empty id
        ("nope", "a", ARTIFACT_LOG, _DIGEST),  # unknown experiment
    ]
    for i, (eid, aid, kind, ref) in enumerate(cases):
        try:
            mon.artifact(eid, aid, kind, ref, 10 + i)
        except ExperimentTrackingError:
            pass
        else:
            raise AssertionError(f"expected refusal for {kind!r}/{ref!r}")
    mon.artifact("exp-1", "a", ARTIFACT_LOG, _DIGEST, 50)
    try:
        mon.artifact("exp-1", "a", ARTIFACT_LOG, _DIGEST, 51)
    except DuplicateArtifactError:
        pass
    else:
        raise AssertionError("expected DuplicateArtifactError")


# --- compare ----------------------------------------------------------------


def test_compare_best_is_data():
    mon = fresh()
    make_exp(mon, seq=0, eid="a", config={"lr": 0.1})
    make_exp(mon, seq=1, eid="b", config={"lr": 0.01})
    mon.log("a", {"loss": 0.9}, 2)
    mon.log("a", {"loss": 0.7}, 3)
    mon.log("b", {"loss": 0.5}, 4)
    report = mon.compare(["a", "b"], "loss", 4, direction=DIR_MIN)
    assert report.best_id == "b"
    assert [r.experiment_id for r in report.rows] == ["b", "a"]
    assert report.verify(seed="t")
    assert report.aggregation == AGG_LAST
    # audited read: seq not consumed
    assert mon.stats()["last_seq"] == 4


def test_compare_aggregations_and_directions():
    mon = fresh()
    make_exp(mon, seq=0, eid="a")
    make_exp(mon, seq=1, eid="b")
    for i, v in enumerate((0.9, 0.1, 0.5)):
        mon.log("a", {"loss": v}, 2 + i)
    mon.log("b", {"loss": 0.4}, 5)
    r_min = mon.compare(["a", "b"], "loss", 5, aggregation=AGG_MIN, direction=DIR_MIN)
    assert r_min.best_id == "a"
    r_max = mon.compare(["a", "b"], "loss", 5, aggregation=AGG_MAX, direction=DIR_MAX)
    assert r_max.best_id == "a"
    r_mean = mon.compare(["a", "b"], "loss", 5, aggregation=AGG_MEAN, direction=DIR_MIN)
    assert r_mean.best_id == "b"  # mean(a)=0.5 > 0.4
    r_last = mon.compare(["a", "b"], "loss", 5, aggregation=AGG_LAST, direction=DIR_MIN)
    assert r_last.best_id == "b"


def test_compare_excludes_missing_metric_as_data():
    mon = fresh()
    make_exp(mon, seq=0, eid="a")
    make_exp(mon, seq=1, eid="b")
    mon.log("a", {"loss": 0.2}, 2)
    mon.log("b", {"acc": 0.9}, 3)
    report = mon.compare(["a", "b"], "loss", 3, direction=DIR_MIN)
    assert report.best_id == "a"
    assert report.excluded == ("b",)
    assert [r.experiment_id for r in report.rows] == ["a"]


def test_compare_bad_inputs():
    mon = fresh()
    make_exp(mon, seq=0, eid="a")
    mon.log("a", {"loss": 0.2}, 1)
    bad_calls = [
        ([], "loss", 2, AGG_LAST, DIR_MAX),  # empty ids
        (["a", "a"], "loss", 2, AGG_LAST, DIR_MAX),  # duplicates
        (["nope"], "loss", 2, AGG_LAST, DIR_MAX),  # unknown experiment
        (["a"], "", 2, AGG_LAST, DIR_MAX),  # empty metric
        (["a"], "loss", 2, "median", DIR_MAX),  # bad aggregation
        (["a"], "loss", 2, AGG_LAST, "sideways"),  # bad direction
        (["a"], "loss", -1, AGG_LAST, DIR_MAX),  # bad seq
    ]
    for ids, metric, seq, agg, direction in bad_calls:
        try:
            mon.compare(ids, metric, seq, aggregation=agg, direction=direction)
        except ExperimentTrackingError:
            pass
        else:
            raise AssertionError(f"expected refusal for {ids!r}/{agg!r}")


# --- views / audit ------------------------------------------------------------


def test_views_and_stats():
    mon = fresh()
    make_exp(mon, seq=0, eid="b")
    make_exp(mon, seq=1, eid="a")
    assert mon.experiment_ids() == ("a", "b")
    mon.log("a", {"loss": 0.1}, 2)
    assert len(mon.metrics_for("a")) == 1
    assert mon.metrics_for("b") == ()
    mon.artifact("a", "ds", ARTIFACT_DATASET, _DIGEST, 3)
    assert len(mon.artifacts_for("a")) == 1
    st = mon.stats()
    assert st == {
        "experiments": 2,
        "metric_logs": 1,
        "artifacts": 1,
        "comparisons": 0,
        "last_seq": 3,
    }
    try:
        mon.experiment("nope")
    except UnknownExperimentError:
        pass
    else:
        raise AssertionError("expected UnknownExperimentError")
    snap = mon.as_dict()
    assert snap["version"] == EXPERIMENT_TRACKING_VERSION
    assert set(snap["experiments"]) == {"a", "b"}


def test_audit_shapes_and_bad_kind():
    mon = fresh()
    make_exp(mon, seq=0)
    mon.log("exp-1", {"loss": 0.1}, 1)
    mon.artifact("exp-1", "c", ARTIFACT_MODEL, _DIGEST, 2)
    mon.compare(["exp-1"], "loss", 2)
    kinds = [e["kind"] for e in mon.audit_log()]
    assert kinds == [
        KIND_EXPERIMENT_CREATED,
        KIND_METRIC_LOGGED,
        KIND_ARTIFACT_BOUND,
        KIND_COMPARED,
    ]
    for e in mon.audit_log():
        assert e["schema"] == AUDIT_SCHEMA
        assert e["module"] == "experiment_tracking"
    ev = experiment_tracking_audit_event(KIND_COMPARED, 9, best_id="exp-1")
    assert ev["seq"] == 9 and ev["detail"]["best_id"] == "exp-1"
    try:
        experiment_tracking_audit_event("experiment.nope", 0)
    except ExperimentTrackingError:
        pass
    else:
        raise AssertionError("expected refusal for bad audit kind")


def test_digest_determinism_across_instances():
    m1, m2 = fresh(seed="same"), fresh(seed="same")
    for mon, s in ((m1, 0), (m2, 0)):
        mon.create_experiment("e", "n", {"lr": 0.5}, s)
        mon.log("e", {"loss": 0.25}, s + 1)
    assert m1.experiment("e").digest == m2.experiment("e").digest
    assert m1.metric_log("log-0").digest == m2.metric_log("log-0").digest


def test_main_selfcheck(capsys=None):
    import subprocess

    out = subprocess.run(
        [sys.executable, MODULE_PATH], capture_output=True, text=True, cwd="/tmp"
    )
    assert out.returncode == 0, out.stderr
    assert "experiment-tracking OK" in out.stdout
