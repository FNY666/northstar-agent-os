"""Tests for model_serving.py (15 tests)."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import model_serving
from model_serving import (
    MODEL_SERVING_VERSION,
    SCHEMA_PIN,
    AUDIT_SCHEMA,
    FRAMEWORKS,
    ModelServing,
    BadServiceError,
    DuplicateServiceError,
    RetiredServiceError,
    UnknownServiceError,
    BadModelError,
    BadFrameworkError,
    BadReplicaError,
    BadCanaryError,
    BadOutcomeError,
    BadReasonError,
    ServiceStateError,
    SeqOrderError,
    AuditKindError,
    model_serving_audit_event,
)

DIGEST = "sha256:" + "ab" * 32
DIGEST2 = "sha256:" + "cd" * 32


def fresh():
    return ModelServing()


def test_version_and_schema_pins():
    assert MODEL_SERVING_VERSION == "model-serving.v1"
    assert SCHEMA_PIN == "northstar.model-serving.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"
    assert "sklearn" in FRAMEWORKS and "triton" in FRAMEWORKS


def test_stdlib_only():
    src = Path(model_serving.__file__).read_text()
    tree = ast.parse(src)
    allowed = {
        "hashlib",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "builtins",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_deploy_roundtrip():
    ms = fresh()
    rec = ms.deploy(
        "svc-1", DIGEST, 1, framework="sklearn",
        replicas=2, min_replicas=1, max_replicas=4, canary_pct=10,
    )
    assert rec.service_id == "svc-1"
    assert rec.status == "deploying"
    assert rec.verify()
    view = ms.service("svc-1", 1)
    assert view.status == "deploying" and view.replicas == 2
    assert view.verify()


def test_deploy_duplicate_refused():
    ms = fresh()
    ms.deploy("svc-1", DIGEST, 1)
    with pytest.raises(DuplicateServiceError):
        ms.deploy("svc-1", DIGEST2, 2)
    # failed mutation consumed its seq + booked a rejected row
    rows = ms.audit_log()
    assert rows[-1]["kind"] == "rejected"
    assert rows[-1]["seq"] == 2
    with pytest.raises(SeqOrderError):
        ms.deploy("svc-2", DIGEST, 2)


def test_deploy_bad_inputs():
    ms = fresh()
    seq = 0
    bad = [
        ("", DIGEST, {}),                       # empty id
        ("svc x", DIGEST, {}),                  # whitespace id
        (123, DIGEST, {}),                      # non-str id
        (True, DIGEST, {}),                     # bool id
        ("svc-1", "nope", {}),                  # bad digest
        ("svc-1", "sha256:" + "zz" * 32, {}),   # non-hex digest
        ("svc-1", DIGEST, {"framework": "keras"}),  # unknown framework
        ("svc-1", DIGEST, {"replicas": 0}),      # zero replicas
        ("svc-1", DIGEST, {"replicas": True}),   # bool replicas
        ("svc-1", DIGEST, {"min_replicas": 3, "max_replicas": 2}),  # min>max
        ("svc-1", DIGEST, {"replicas": 5, "min_replicas": 1, "max_replicas": 2}),  # out of budget
        ("svc-1", DIGEST, {"canary_pct": 101}),  # canary > 100
        ("svc-1", DIGEST, {"canary_pct": -1}),   # canary negative
    ]
    for svc_id, digest, kw in bad:
        seq += 1
        with pytest.raises(model_serving.ModelServingError):
            ms.deploy(svc_id, digest, seq, **kw)


def test_ready_lifecycle():
    ms = fresh()
    ms.deploy("svc-1", DIGEST, 1)
    rdy = ms.ready("svc-1", 2)
    assert rdy.verify()
    assert ms.service("svc-1", 2).status == "ready"
    with pytest.raises(ServiceStateError):
        ms.ready("svc-1", 3)  # already ready
    with pytest.raises(UnknownServiceError):
        ms.ready("nope", 4)


def test_scale():
    ms = fresh()
    ms.deploy("svc-1", DIGEST, 1, min_replicas=1, max_replicas=4)
    rec = ms.scale("svc-1", 3, 2)
    assert rec.old_replicas == 1 and rec.new_replicas == 3
    assert rec.verify()
    assert ms.service("svc-1", 2).replicas == 3
    with pytest.raises(BadReplicaError):
        ms.scale("svc-1", 9, 3)  # above max_replicas
    with pytest.raises(BadReplicaError):
        ms.scale("svc-1", 0, 4)  # below 1
    with pytest.raises(UnknownServiceError):
        ms.scale("nope", 5, 5)


def test_predict_roundtrip():
    ms = fresh()
    ms.deploy("svc-1", DIGEST, 1)
    ms.ready("svc-1", 2)
    pred = ms.predict("svc-1", 3, input_digest=DIGEST2, outcome="queued")
    assert pred.pred_id == "pred-1"
    assert pred.outcome == "queued"
    assert pred.verify()
    assert ms.prediction("pred-1", 3).verify()
    pred2 = ms.predict("svc-1", 4)  # no input digest is allowed
    assert pred2.pred_id == "pred-2"
    with pytest.raises(BadOutcomeError):
        ms.predict("svc-1", 5, outcome="answered")


def test_predict_refused_when_not_ready():
    ms = fresh()
    ms.deploy("svc-1", DIGEST, 1)
    with pytest.raises(ServiceStateError):
        ms.predict("svc-1", 2)  # still deploying
    with pytest.raises(UnknownServiceError):
        ms.predict("nope", 3)


def test_undeploy_terminal():
    ms = fresh()
    ms.deploy("svc-1", DIGEST, 1)
    ms.ready("svc-1", 2)
    rec = ms.undeploy("svc-1", 3, reason="replaced")
    assert rec.verify()
    with pytest.raises(RetiredServiceError):
        ms.service("svc-1", 3)
    with pytest.raises(RetiredServiceError):
        ms.deploy("svc-1", DIGEST, 4)  # id never recycled
    with pytest.raises((UnknownServiceError, RetiredServiceError)):
        ms.scale("svc-1", 2, 5)
    with pytest.raises(BadReasonError):
        ms.deploy("svc-2", DIGEST, 6)
        ms.undeploy("svc-2", 7, reason="vibes")


def test_seq_ordering():
    ms = fresh()
    with pytest.raises(SeqOrderError):
        ms.deploy("svc-1", DIGEST, 0)  # first seq must be >= 1
    ms.deploy("svc-1", DIGEST, 1)
    for bad in (True, "2", 1.0, -1):
        with pytest.raises(SeqOrderError):
            ms.ready("svc-1", bad)
    with pytest.raises(SeqOrderError):
        ms.ready("svc-1", 1)  # rewind
    # rewind does not consume: next valid seq still works
    ms.ready("svc-1", 2)


def test_views_pure():
    ms = fresh()
    ms.deploy("svc-1", DIGEST, 1)
    ms.ready("svc-1", 2)
    before = len(ms.audit_log())
    assert ms.service_ids(2) == ("svc-1",)
    stats = ms.stats(2)
    assert stats["active_services"] == 1 and stats["predictions"] == 0
    assert ms.service_ids(2) == ("svc-1",)  # same seq twice OK
    assert len(ms.audit_log()) == before  # pure reads write no rows


def test_audit_shapes_and_banned_keys():
    ms = fresh()
    row = model_serving_audit_event("deployed", {"service_id": "s"}, 1)
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == MODEL_SERVING_VERSION
    with pytest.raises(AuditKindError):
        model_serving_audit_event("nope", {}, 1)
    with pytest.raises(AuditKindError):
        model_serving_audit_event("deployed", {"uri": "s3://x"}, 1)
    with pytest.raises(AuditKindError):
        model_serving_audit_event("predicted", {"input": "raw"}, 1)
    with pytest.raises(AuditKindError):
        model_serving_audit_event("deployed", {"payload": b"bytes"}, 1)


def test_digest_determinism_and_tamper():
    ms1, ms2 = fresh(), fresh()
    r1 = ms1.deploy("svc-1", DIGEST, 1, framework="onnx")
    r2 = ms2.deploy("svc-1", DIGEST, 1, framework="onnx")
    assert r1.digest == r2.digest  # cross-instance determinism
    tampered = model_serving.DeploymentRecord(
        **{**r1.__dict__, "replicas": 99}
    )
    assert not tampered.verify()


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, model_serving.__file__],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0
    assert "model-serving OK" in proc.stdout
