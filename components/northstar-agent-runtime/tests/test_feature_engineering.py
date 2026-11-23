"""Tests for feature_engineering.py (15 tests)."""

from __future__ import annotations

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import feature_engineering as fe_mod
from feature_engineering import (
    AuditKindError,
    BadEncodeError,
    BadScaleError,
    BadTransformError,
    BadValueError,
    DuplicateTransformError,
    FeatureEngineering,
    FeatureEngineeringError,
    SeqOrderError,
    UnknownTransformError,
    feature_engineering_audit_event,
)

MODULE = Path(fe_mod.__file__)


def test_version_and_schema_pins():
    assert fe_mod.FEATURE_ENGINEERING_VERSION == "feature-engineering.v1"
    assert fe_mod.SCHEMA_PIN == "northstar.feature-engineering.v1"


def test_stdlib_only():
    tree = ast.parse(MODULE.read_text())
    allowed = {
        "hashlib", "math", "threading", "dataclasses", "typing",
        "__future__", "json", "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_register_transform_roundtrip_and_verify():
    fe = FeatureEngineering()
    rec = fe.register_transform("z1", "standard", 1, {"mean": 10.0, "std": 2.0})
    assert rec.kind == "standard"
    assert rec.verify()
    assert fe.transform_record("z1") == rec
    assert fe.transform_ids() == ("z1",)
    assert rec.digest.startswith("sha256:")


def test_register_bad_kind_duplicate_seq_burn():
    fe = FeatureEngineering()
    with pytest.raises(BadTransformError):
        fe.register_transform("x", "nope", 1)
    # failed mutation consumed seq 1
    with pytest.raises(SeqOrderError):
        fe.register_transform("y", "identity", 1)
    fe.register_transform("a", "identity", 2)
    with pytest.raises(DuplicateTransformError):
        fe.register_transform("a", "identity", 3)
    rows = [r for r in fe.audit_log() if r["kind"] == "feature-engineering.rejected"]
    assert len(rows) == 2


def test_transform_standard_and_minmax():
    fe = FeatureEngineering()
    fe.register_transform("z", "standard", 1, {"mean": 10.0, "std": 2.0})
    out = fe.transform("age", "z", 14.0, 2)
    assert out.output == pytest.approx(2.0)
    fe.register_transform("m", "minmax", 3, {"min": 0.0, "max": 100.0})
    out2 = fe.transform("pct", "m", 50.0, 4)
    assert out2.output == pytest.approx(0.5)
    assert out.output_digest.startswith("sha256:")
    assert out.input_digest.startswith("sha256:")


def test_transform_onehot_label_bin_log_sqrt_interaction_identity():
    fe = FeatureEngineering()
    fe.register_transform("oh", "onehot", 1, {"categories": ["a", "b"]})
    assert fe.transform("c", "oh", "a", 2).output == {"a": 1, "b": 0}
    fe.register_transform("lb", "label", 3, {"categories": ["x", "y"]})
    assert fe.transform("c", "lb", "y", 4).output == 1
    fe.register_transform("bn", "bin", 5, {"edges": [10.0, 20.0]})
    assert fe.transform("v", "bn", 5.0, 6).output == 0
    assert fe.transform("v", "bn", 25.0, 7).output == 2
    fe.register_transform("lg", "log", 8)
    assert fe.transform("v", "lg", 1.0, 9).output == pytest.approx(0.0)
    fe.register_transform("sq", "sqrt", 10)
    assert fe.transform("v", "sq", 4.0, 11).output == pytest.approx(2.0)
    fe.register_transform("ix", "interaction", 12, {"with_": 3.0})
    assert fe.transform("v", "ix", 4.0, 13).output == pytest.approx(12.0)
    fe.register_transform("id", "identity", 14)
    assert fe.transform("v", "id", "raw", 15).output == "raw"


def test_transform_unknown_bad_value_domain_errors():
    fe = FeatureEngineering()
    fe.register_transform("lg", "log", 1)
    with pytest.raises(UnknownTransformError):
        fe.transform("v", "missing", 1.0, 2)
    with pytest.raises(BadValueError):
        fe.transform("v", "lg", -1.0, 3)  # log of negative
    with pytest.raises(BadValueError):
        fe.transform("v", "lg", float("nan"), 4)
    with pytest.raises(BadValueError):
        fe.transform("v", "lg", 2 ** 60, 5)  # unsafe int
    fe.register_transform("oh", "onehot", 6, {"categories": ["a"]})
    with pytest.raises(BadValueError):
        fe.transform("v", "oh", "zzz", 7)  # unknown category


def test_encode_label_and_onehot():
    fe = FeatureEngineering()
    rec = fe.encode("city", "y", 1, strategy="label", categories=("x", "y"))
    assert rec.output == 1
    rec2 = fe.encode("city", "x", 2, strategy="onehot", categories=("x", "y"))
    assert rec2.output == {"x": 1, "y": 0}
    with pytest.raises(BadEncodeError):
        fe.encode("city", "z", 3, strategy="label", categories=("x", "y"))
    with pytest.raises(BadEncodeError):
        fe.encode("city", "x", 4, strategy="weird", categories=("x",))


def test_scale_strategies_fit_and_host_params():
    fe = FeatureEngineering()
    sc = fe.scale("s", [1.0, 2.0, 3.0], 1, strategy="minmax")
    assert sc.outputs == pytest.approx((0.0, 0.5, 1.0))
    sc2 = fe.scale("s", [1.0, 2.0, 3.0], 2, strategy="standard")
    assert abs(sc2.outputs[1]) < 1e-12  # mean-centered
    # host-supplied params
    sc3 = fe.scale("s", [10.0, 20.0], 3, strategy="minmax",
                   params={"min": 0.0, "max": 40.0})
    assert sc3.outputs == pytest.approx((0.25, 0.5))
    with pytest.raises(BadScaleError):
        fe.scale("s", [1.0, 1.0], 4, strategy="minmax")  # zero range
    with pytest.raises(BadScaleError):
        fe.scale("s", [], 5)  # empty values
    with pytest.raises(BadScaleError):
        fe.scale("s", [1.0], 6, strategy="nope")


def test_scale_robust_fit():
    fe = FeatureEngineering()
    sc = fe.scale("r", [1.0, 2.0, 3.0, 4.0, 5.0], 1, strategy="robust")
    assert sc.outputs[2] == pytest.approx(0.0)  # median-centered
    assert len(sc.outputs) == 5


def test_seq_ordering_bool_refused():
    fe = FeatureEngineering()
    fe.register_transform("a", "identity", 1)
    with pytest.raises(SeqOrderError):
        fe.register_transform("b", "identity", 1)  # rewind
    with pytest.raises(SeqOrderError):
        fe.register_transform("b", "identity", True)
    with pytest.raises(SeqOrderError):
        fe.transform("v", "a", 1.0, "2")


def test_type_tagged_digests_bool_vs_int():
    fe = FeatureEngineering()
    fe.register_transform("id", "identity", 1)
    o1 = fe.transform("v", "id", True, 2)
    o2 = fe.transform("v", "id", 1, 3)
    assert o1.output_digest != o2.output_digest


def test_audit_shapes_banned_keys_bad_kind():
    fe = FeatureEngineering()
    fe.register_transform("z", "standard", 1, {"mean": 0.0, "std": 1.0})
    fe.transform("v", "z", 1.0, 2)
    kinds = {r["kind"] for r in fe.audit_log()}
    assert "feature-engineering.transform-registered" in kinds
    assert "feature-engineering.transformed" in kinds
    for row in fe.audit_log():
        assert row["schema"] == "audit.ndjson/1"
        for banned in ("value", "payload", "raw", "body", "data", "text"):
            assert banned not in row["detail"], banned
    with pytest.raises(AuditKindError):
        feature_engineering_audit_event("bogus", 1)
    with pytest.raises(FeatureEngineeringError):
        feature_engineering_audit_event("transformed", 1, value=1)


def test_concurrency_smoke():
    fe = FeatureEngineering()
    fe.register_transform("id", "identity", 1)

    def work(n):
        fe.transform("v", "id", n, n + 2)

    threads = [threading.Thread(target=work, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(fe.outcomes()) == 4


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, str(MODULE)], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, proc.stderr
    assert "feature-engineering OK" in proc.stdout
